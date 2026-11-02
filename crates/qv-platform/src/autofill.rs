// SPDX-License-Identifier: AGPL-3.0-or-later

//! Android autofill identity matching (0009 §4.4, 0008 §3). Matching is exact:
//! an OS-verified package plus its full signer set, or an exact web origin
//! reported by an allowlisted browser. Titles, labels and URL substrings are
//! never inspected. Every parser is bounded and returns `None` rather than a
//! "best effort" identity, so a malformed stored value can never match.
use crate::PlatformError;
use std::time::Duration;

/// Longest accepted Android package name.
pub const MAX_PACKAGE: usize = 255;
/// Most signing certificates in one identity.
pub const MAX_SIGNERS: usize = 8;
/// Longest accepted DNS host name.
pub const MAX_HOST: usize = 253;
/// Stored `url` values longer than this are not considered identities.
pub const MAX_IDENTITY_FIELD: usize = 1024;
/// Largest username or password returned to the OS for one fill.
pub const MAX_FILL_VALUE: usize = 8 * 1024;
/// A pending request not yet bound to an unlocked session expires after this.
pub const REQUEST_TTL: Duration = Duration::from_secs(120);
/// Stored app identity scheme (a client convention, 0003 §5.2).
pub const APP_SCHEME: &str = "androidapp://";
const DIGEST_MARK: &str = "#sha256=";

/// A syntactically valid Android package name (segments `[A-Za-z][A-Za-z0-9_]*`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackageName(String);
impl PackageName {
    /// Validate an exact package name; no normalization.
    pub fn parse(name: &str) -> Option<Self> {
        if name.is_empty() || name.len() > MAX_PACKAGE {
            return None;
        }
        let mut segments = 0;
        for segment in name.split('.') {
            let mut chars = segment.bytes();
            if !chars.next().is_some_and(|c| c.is_ascii_alphabetic())
                || !chars.all(|c| c.is_ascii_alphanumeric() || c == b'_')
            {
                return None;
            }
            segments += 1;
        }
        (segments >= 2).then(|| Self(name.to_owned()))
    }
    /// The package name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A complete, sorted, duplicate-free set of SHA-256 signing-certificate digests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignerSet(Vec<[u8; 32]>);
impl SignerSet {
    /// Build from digests; empty, oversized or duplicated sets are refused.
    pub fn new(digests: &[[u8; 32]]) -> Option<Self> {
        if digests.is_empty() || digests.len() > MAX_SIGNERS {
            return None;
        }
        let mut set = digests.to_vec();
        set.sort_unstable();
        set.dedup();
        (set.len() == digests.len()).then_some(Self(set))
    }
    /// Parse `n * 32` bytes as delivered by the native glue.
    pub fn from_flat(bytes: &[u8]) -> Option<Self> {
        if bytes.is_empty() || !bytes.len().is_multiple_of(32) || bytes.len() > MAX_SIGNERS * 32 {
            return None;
        }
        Self::new(bytes.as_chunks::<32>().0)
    }
    /// The sorted digests.
    pub fn digests(&self) -> &[[u8; 32]] {
        &self.0
    }
}

/// An OS-verified requesting app: system-reported package and signer set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppIdentity {
    /// Package name from the system's activity component.
    pub package: PackageName,
    /// All current signing certificates.
    pub signers: SignerSet,
}
impl AppIdentity {
    /// The stored-field form `androidapp://<package>#sha256=<hex>[,<hex>…]`.
    pub fn to_url(&self) -> String {
        let digests: Vec<String> = self.signers.0.iter().map(hex).collect();
        format!(
            "{APP_SCHEME}{}{DIGEST_MARK}{}",
            self.package.0,
            digests.join(",")
        )
    }
    fn parse_stored(rest: &str) -> Option<Self> {
        let (package, digests) = rest.split_once(DIGEST_MARK)?;
        let package = PackageName::parse(package)?;
        let mut set = Vec::new();
        for digest in digests.split(',') {
            set.push(unhex(digest)?);
            if set.len() > MAX_SIGNERS {
                return None;
            }
        }
        Some(Self {
            package,
            signers: SignerSet::new(&set)?,
        })
    }
}

/// Web schemes that may be matched, each only against itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheme {
    /// `https`, default port 443.
    Https,
    /// `http`, default port 80.
    Http,
}
impl Scheme {
    fn parse(scheme: &str) -> Option<Self> {
        if scheme.eq_ignore_ascii_case("https") {
            Some(Self::Https)
        } else if scheme.eq_ignore_ascii_case("http") {
            Some(Self::Http)
        } else {
            None
        }
    }
    fn default_port(self) -> u16 {
        match self {
            Self::Https => 443,
            Self::Http => 80,
        }
    }
}

/// An exact web origin: scheme, lowercase ASCII host and port.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Origin {
    scheme: Scheme,
    host: String,
    port: u16,
}
impl Origin {
    /// Parse a stored `http(s)://host[:port][/…]` value. Userinfo, IPv6
    /// literals, non-ASCII or percent-encoded hosts and bad ports are refused.
    pub fn parse_stored(url: &str) -> Option<Self> {
        let (scheme, rest) = url.split_once("://")?;
        let scheme = Scheme::parse(scheme)?;
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let authority = &rest[..end];
        if authority.contains(['@', '[', ']']) {
            return None;
        }
        let (host, port) = match authority.split_once(':') {
            Some((host, port)) => (host, parse_port(port)?),
            None => (authority, scheme.default_port()),
        };
        Some(Self {
            scheme,
            host: parse_host(host)?,
            port,
        })
    }
    /// The browser-reported origin. Android reports no port, so the scheme's
    /// default applies; a stored non-default port therefore never matches.
    pub fn from_request(scheme: &str, host: &str) -> Option<Self> {
        let scheme = Scheme::parse(scheme)?;
        Some(Self {
            scheme,
            host: parse_host(host)?,
            port: scheme.default_port(),
        })
    }
    /// Display form for the requester banner.
    pub fn display(&self) -> String {
        let scheme = match self.scheme {
            Scheme::Https => "https",
            Scheme::Http => "http",
        };
        if self.port == self.scheme.default_port() {
            format!("{scheme}://{}", self.host)
        } else {
            format!("{scheme}://{}:{}", self.host, self.port)
        }
    }
}

fn parse_port(port: &str) -> Option<u16> {
    if port.is_empty() || port.len() > 5 || !port.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    port.parse::<u16>().ok().filter(|p| *p != 0)
}

fn parse_host(host: &str) -> Option<String> {
    if host.is_empty() || host.len() > MAX_HOST || !host.is_ascii() {
        return None;
    }
    let host = host.to_ascii_lowercase();
    for label in host.split('.') {
        let bytes = label.as_bytes();
        if bytes.is_empty()
            || bytes.len() > 63
            || bytes[0] == b'-'
            || bytes[bytes.len() - 1] == b'-'
            || !bytes
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
        {
            return None;
        }
    }
    Some(host)
}

fn hex(digest: &[u8; 32]) -> String {
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Option<[u8; 32]> {
    let bytes = text.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let nibble = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let mut out = [0; 32];
    for (i, pair) in bytes.as_chunks::<2>().0.iter().enumerate() {
        out[i] = nibble(pair[0])? << 4 | nibble(pair[1])?;
    }
    Some(out)
}

/// A browser whose reported web origins are trusted, pinned by signer set.
pub struct TrustedBrowser {
    /// Exact package name.
    pub package: &'static str,
    /// Exact signing-certificate digest set.
    pub signers: &'static [[u8; 32]],
}
/// Device-validated browsers only; entries are added solely from digests
/// observed on a validation device and recorded in plan 0034 VALIDATION.md.
pub const TRUSTED_BROWSERS: &[TrustedBrowser] = &[];

/// Field roles present in the request.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Roles {
    /// A username/email field was detected.
    pub username: bool,
    /// A password field was detected.
    pub password: bool,
}

/// A validated request: OS-verified app plus an optional claimed origin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FillRequest {
    /// The requesting app.
    pub app: AppIdentity,
    /// Origin claimed by the app; trusted only for an allowlisted browser.
    pub web: Option<Origin>,
    /// Detected roles; at least one.
    pub roles: Roles,
}

/// Whom a fill would be released to, after browser trust is decided.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Requester {
    /// A native app; only linked app identities match.
    App(AppIdentity),
    /// A trusted browser showing an exact origin; only stored origins match.
    Web {
        /// The allowlisted browser.
        browser: AppIdentity,
        /// The reported origin.
        origin: Origin,
    },
}

/// An identity stored in an entry's `url` field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoredIdentity {
    /// `androidapp://…` with a complete signer set.
    App(AppIdentity),
    /// `http(s)://…` exact origin.
    Web(Origin),
}
impl StoredIdentity {
    /// Parse a stored field value; anything not exactly recognized is `None`.
    pub fn parse(value: &[u8]) -> Option<Self> {
        if value.len() > MAX_IDENTITY_FIELD {
            return None;
        }
        let text = std::str::from_utf8(value).ok()?.trim_ascii();
        if let Some(rest) = text.strip_prefix(APP_SCHEME) {
            return AppIdentity::parse_stored(rest).map(Self::App);
        }
        Origin::parse_stored(text).map(Self::Web)
    }
}

impl FillRequest {
    /// Validate the native request. The web origin is optional and dropped
    /// (not trusted) whenever its scheme or host is unusable.
    pub fn new(
        package: &str,
        signers: &[u8],
        web_scheme: Option<&str>,
        web_host: Option<&str>,
        roles: Roles,
    ) -> Result<Self, PlatformError> {
        let app = AppIdentity {
            package: PackageName::parse(package).ok_or(PlatformError::InvalidInput)?,
            signers: SignerSet::from_flat(signers).ok_or(PlatformError::InvalidInput)?,
        };
        if !roles.username && !roles.password {
            return Err(PlatformError::InvalidInput);
        }
        let web = match (web_scheme, web_host) {
            (Some(s), Some(h)) => Origin::from_request(s, h),
            _ => None,
        };
        Ok(Self { app, web, roles })
    }
    /// A claimed origin counts only for an exactly pinned trusted browser.
    pub fn requester(&self, trusted: &[TrustedBrowser]) -> Requester {
        let browser = trusted.iter().any(|t| {
            t.package == self.app.package.as_str()
                && SignerSet::new(t.signers).is_some_and(|s| s == self.app.signers)
        });
        match (&self.web, browser) {
            (Some(origin), true) => Requester::Web {
                browser: self.app.clone(),
                origin: origin.clone(),
            },
            _ => Requester::App(self.app.clone()),
        }
    }
}

/// Exact identity equality; app and web identities never match each other.
pub fn matches(requester: &Requester, stored: &StoredIdentity) -> bool {
    match (requester, stored) {
        (Requester::App(app), StoredIdentity::App(s)) => app == s,
        (Requester::Web { origin, .. }, StoredIdentity::Web(s)) => origin == s,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    const A: [u8; 32] = [0xaa; 32];
    const B: [u8; 32] = [0xbb; 32];
    const BROWSER: &[TrustedBrowser] = &[TrustedBrowser {
        package: "org.example.browser",
        signers: &[A],
    }];
    fn roles() -> Roles {
        Roles {
            username: true,
            password: true,
        }
    }
    fn app(package: &str, signers: &[[u8; 32]]) -> FillRequest {
        FillRequest::new(package, &signers.concat(), None, None, roles()).unwrap()
    }
    fn web(package: &str, host: &str) -> Requester {
        FillRequest::new(package, &A, Some("https"), Some(host), roles())
            .unwrap()
            .requester(BROWSER)
    }
    fn stored(s: &str) -> StoredIdentity {
        StoredIdentity::parse(s.as_bytes()).unwrap()
    }

    #[test]
    fn autofill_web_origin_matches_exactly_and_refuses_substring_spoofs() {
        let bank = stored("https://Bank.Example/login?x=1");
        assert!(matches(&web("org.example.browser", "bank.example"), &bank));
        assert!(matches(&web("org.example.browser", "BANK.example"), &bank));
        for spoof in [
            "bank.example.evil.test",
            "evilbank.example",
            "login.bank.example",
            "example",
            "bank.exampl",
        ] {
            assert!(
                !matches(&web("org.example.browser", spoof), &bank),
                "{spoof}"
            );
        }
        // A subdomain entry does not match its parent either.
        assert!(!matches(
            &web("org.example.browser", "bank.example"),
            &stored("https://login.bank.example")
        ));
        // Scheme and port are exact; the request carries default ports only.
        let plain = FillRequest::new(
            "org.example.browser",
            &A,
            Some("http"),
            Some("bank.example"),
            roles(),
        )
        .unwrap()
        .requester(BROWSER);
        assert!(!matches(&plain, &bank));
        assert!(matches(&plain, &stored("http://bank.example:80/")));
        assert!(matches(
            &web("org.example.browser", "bank.example"),
            &stored("https://bank.example:443")
        ));
        assert!(!matches(
            &web("org.example.browser", "bank.example"),
            &stored("https://bank.example:8443")
        ));
    }

    #[test]
    fn autofill_stored_identity_parser_refuses_ambiguous_forms() {
        for bad in [
            "https://bank.example@evil.test",
            "https://user:pw@bank.example",
            "https://[::1]/",
            "https://bänk.example",
            "https://bank%2eexample",
            "https://bank.example./",
            "https://.bank.example",
            "https://-bank.example",
            "https://bank.example:0",
            "https://bank.example:65536",
            "https://bank.example:",
            "https://",
            "bank.example",
            "bank://login",
            "android-app://com.bank.app",
            "intent://bank.example#Intent;scheme=https;end",
            "javascript://bank.example",
            "ftp://bank.example",
        ] {
            assert!(StoredIdentity::parse(bad.as_bytes()).is_none(), "{bad}");
        }
        let long = format!("https://{}.example", "a".repeat(MAX_IDENTITY_FIELD));
        assert!(StoredIdentity::parse(long.as_bytes()).is_none());
        assert!(StoredIdentity::parse(&[0xff, 0xfe]).is_none());
        assert_eq!(
            stored(" https://bank.example "),
            stored("https://bank.example")
        );
    }

    #[test]
    fn autofill_app_identity_requires_package_and_exact_signer_set() {
        let linked = app("com.bank.app", &[A, B]).app;
        let url = linked.to_url();
        assert!(url.starts_with("androidapp://com.bank.app#sha256="));
        let s = stored(&url);
        assert!(matches(&Requester::App(linked.clone()), &s));
        // Signer order does not matter; subsets, supersets and other keys do.
        assert!(matches(&app("com.bank.app", &[B, A]).requester(&[]), &s));
        assert!(!matches(&app("com.bank.app", &[A]).requester(&[]), &s));
        assert!(!matches(
            &app("com.bank.app", &[[0xcc; 32]]).requester(&[]),
            &s
        ));
        assert!(!matches(&app("com.bank.app2", &[A, B]).requester(&[]), &s));
        let digest = "a".repeat(64);
        for bad in [
            "androidapp://com.bank.app".to_owned(),
            "androidapp://com.bank.app#sha256=".to_owned(),
            format!("androidapp://com.bank.app#sha256={}", "A".repeat(64)),
            format!("androidapp://com.bank.app#sha256={}", "a".repeat(62)),
            format!("androidapp://com.bank.app#sha256={digest},{digest}"),
            format!("androidapp://com.bank.app#sha256={digest},"),
            format!("androidapp://bank#sha256={digest}"),
            format!("androidapp://com.1bank.app#sha256={digest}"),
            format!("androidapp://com..app#sha256={digest}"),
            format!(
                "androidapp://com.bank.app#sha256={}",
                (0..9)
                    .map(|i| format!("{i:064x}"))
                    .collect::<Vec<_>>()
                    .join(",")
            ),
        ] {
            assert!(StoredIdentity::parse(bad.as_bytes()).is_none(), "{bad}");
        }
    }

    #[test]
    fn autofill_untrusted_app_cannot_claim_a_web_origin() {
        let bank = stored("https://bank.example");
        // Any WebView app may report a domain; without allowlisting it is an
        // app request, and stored origins (and titles/labels) never match it.
        let r = FillRequest::new(
            "com.evil.app",
            &A,
            Some("https"),
            Some("bank.example"),
            roles(),
        )
        .unwrap();
        assert!(matches!(r.requester(BROWSER), Requester::App(_)));
        assert!(!matches(&r.requester(BROWSER), &bank));
        // A browser package re-signed by someone else is not trusted.
        let r = FillRequest::new(
            "org.example.browser",
            &B,
            Some("https"),
            Some("bank.example"),
            roles(),
        )
        .unwrap();
        assert!(!matches(&r.requester(BROWSER), &bank));
        // The production allowlist starts empty.
        assert!(TRUSTED_BROWSERS.is_empty());
        let r = FillRequest::new(
            "org.example.browser",
            &A,
            Some("https"),
            Some("bank.example"),
            roles(),
        )
        .unwrap();
        assert!(!matches(&r.requester(TRUSTED_BROWSERS), &bank));
        // A usable browser origin never matches an app identity, nor vice versa.
        let linked = stored(&app("org.example.browser", &[A]).app.to_url());
        assert!(!matches(
            &web("org.example.browser", "bank.example"),
            &linked
        ));
        // An unusable claimed scheme or host is dropped, never trusted.
        for (s, h) in [
            ("bank", "bank.example"),
            ("https", "bank.example:8443"),
            ("https", ""),
        ] {
            let r = FillRequest::new("org.example.browser", &A, Some(s), Some(h), roles()).unwrap();
            assert!(r.web.is_none());
        }
    }

    #[test]
    fn autofill_request_bounds_are_enforced_before_use() {
        assert!(FillRequest::new("com.bank.app", &[], None, None, roles()).is_err());
        assert!(FillRequest::new("com.bank.app", &[0; 31], None, None, roles()).is_err());
        assert!(FillRequest::new("com.bank.app", &[0; 32 * 9], None, None, roles()).is_err());
        assert!(FillRequest::new("com.bank.app", &[A, A].concat(), None, None, roles()).is_err());
        assert!(FillRequest::new(&"a.".repeat(200), &A, None, None, roles()).is_err());
        assert!(FillRequest::new("com.bank.app", &A, None, None, Roles::default()).is_err());
        assert!(FillRequest::new("com.bank.app", &A, None, None, roles()).is_ok());
        let host = format!("{}.example", "a".repeat(64));
        assert!(Origin::from_request("https", &host).is_none());
        assert!(Origin::from_request("https", &format!("{}a", "a.".repeat(127))).is_none());
        assert!(Origin::from_request("https", &format!("{}a", "a.".repeat(126))).is_some());
    }
}
