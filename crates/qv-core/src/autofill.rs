// SPDX-License-Identifier: AGPL-3.0-or-later

//! Autofill candidates and explicit fill values (0009 §4.3–4.4, 0008 §3).
//! Identity matching is `qv_platform::autofill`; this module only enumerates
//! live entry heads, so a conflicted entry offers each head separately and the
//! frontend must choose one. Values are released only for that chosen head
//! after it is re-read and re-matched.
use crate::platform::autofill::{
    AppIdentity, MAX_FILL_VALUE, Requester, Roles, StoredIdentity, matches,
};
use crate::views::{decrypt, record};
use crate::{CoreError, EntryHandle, Session};
use qv_crypto::SecretBytes;
use qv_model::{
    Entry, Field, FieldKind, FieldValue, Payload, RecordBody, RecordKind, Text, VersionId,
};

/// Field name used for a linked Android app identity.
pub const APP_FIELD_NAME: &str = "Android app";
const USERNAME_NAMES: [&str; 5] = ["username", "user name", "email", "e-mail", "login"];

/// Names one entry head chosen for a fill; opaque to frontends.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CandidateKey {
    entry: EntryHandle,
    version: VersionId,
}
impl core::fmt::Debug for CandidateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("CandidateKey(<redacted>)")
    }
}

/// One fillable entry head. Display data only; no protected value.
pub struct FillCandidate {
    entry: EntryHandle,
    version: VersionId,
    /// The head's title.
    pub title: Text,
    /// The head's username, when that field is not protected.
    pub username: Option<Text>,
    /// The entry has more than one head; this candidate is one of them.
    pub conflicted: bool,
}
impl FillCandidate {
    /// The entry this candidate belongs to.
    pub fn entry(&self) -> EntryHandle {
        self.entry
    }
    /// The head to pass to [`Session::autofill_values`].
    pub fn key(&self) -> CandidateKey {
        CandidateKey {
            entry: self.entry,
            version: self.version,
        }
    }
}
impl core::fmt::Debug for FillCandidate {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("FillCandidate(<redacted>)")
    }
}

/// Values for the requested roles, in protected memory.
pub struct FillValues {
    /// Username, if requested and present.
    pub username: Option<SecretBytes>,
    /// Password, if requested and present.
    pub password: Option<SecretBytes>,
}
impl core::fmt::Debug for FillValues {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("FillValues(<redacted>)")
    }
}

fn entry_of(body: RecordBody) -> Option<Entry> {
    match body {
        RecordBody::Live(Payload::Entry(e)) if e.deleted_at.is_none() => Some(e),
        _ => None,
    }
}

fn identifies(e: &Entry, requester: &Requester) -> bool {
    e.fields.iter().any(|f| {
        f.kind == FieldKind::Url
            && StoredIdentity::parse(f.value.expose_secret())
                .is_some_and(|s| matches(requester, &s))
    })
}

fn named(f: &Field, names: &[&str]) -> bool {
    names
        .iter()
        .any(|n| f.name.expose().trim().eq_ignore_ascii_case(n))
}

/// Deterministic role selection (plan 0034 decision 8).
fn username_field(e: &Entry) -> Option<&Field> {
    e.fields
        .iter()
        .find(|f| named(f, &USERNAME_NAMES))
        .or_else(|| e.fields.iter().find(|f| f.kind == FieldKind::Email))
        .or_else(|| e.fields.iter().find(|f| f.kind == FieldKind::Text))
}
fn password_field(e: &Entry) -> Option<&Field> {
    e.fields
        .iter()
        .find(|f| named(f, &["password"]))
        .or_else(|| e.fields.iter().find(|f| f.kind == FieldKind::Secret))
}

fn copy_value(v: &FieldValue) -> Result<SecretBytes, CoreError> {
    let bytes = v.expose_secret();
    if bytes.is_empty() || bytes.len() > MAX_FILL_VALUE {
        return Err(CoreError::InvalidInput);
    }
    SecretBytes::try_init(bytes.len(), |out| {
        out.copy_from_slice(bytes);
        Ok::<(), CoreError>(())
    })
}

impl Session {
    /// Live entry heads whose `url` fields exactly match `requester`. Titles
    /// and labels are never compared. Order: title, then entry, then head.
    pub fn autofill_candidates(
        &self,
        requester: &Requester,
    ) -> Result<Vec<FillCandidate>, CoreError> {
        self.read(|ctx| {
            let mut out = Vec::new();
            for (id, r) in &ctx.open.index.records {
                ctx.check_cancel()?;
                if r.kind != RecordKind::Entry || !r.status.live || r.status.finally_deleted {
                    continue;
                }
                let mut heads = Vec::new();
                for v in &r.heads {
                    if let Some(e) = entry_of(decrypt(ctx, *id, *v)?.body) {
                        heads.push((*v, e));
                    }
                }
                let conflicted = heads.len() > 1;
                for (version, e) in heads {
                    if !identifies(&e, requester) {
                        continue;
                    }
                    let username = match username_field(&e) {
                        Some(f) if !f.protected => std::str::from_utf8(f.value.expose_secret())
                            .ok()
                            .and_then(|s| Text::new(s).ok()),
                        _ => None,
                    };
                    out.push(FillCandidate {
                        entry: ctx.entry_handle(*id),
                        version,
                        title: e.title,
                        username,
                        conflicted,
                    });
                }
            }
            out.sort_by(|a, b| {
                (a.title.expose(), a.entry, a.version).cmp(&(b.title.expose(), b.entry, b.version))
            });
            Ok(out)
        })
    }

    /// Values of the chosen head for the requested roles. The head must still
    /// exist and still match; otherwise nothing is released.
    pub fn autofill_values(
        &self,
        requester: &Requester,
        candidate: CandidateKey,
        roles: Roles,
    ) -> Result<FillValues, CoreError> {
        self.read(|ctx| {
            ctx.own(candidate.entry.session)?;
            let r = record(&ctx.open.index, candidate.entry.record, RecordKind::Entry)?;
            if !r.status.live || !r.heads.contains(&candidate.version) {
                return Err(CoreError::StaleHandle);
            }
            let e = entry_of(decrypt(ctx, candidate.entry.record, candidate.version)?.body)
                .ok_or(CoreError::StaleHandle)?;
            if !identifies(&e, requester) {
                return Err(CoreError::NotAllowed);
            }
            let username = match (roles.username, username_field(&e)) {
                (true, Some(f)) => Some(copy_value(&f.value)?),
                _ => None,
            };
            let password = match (roles.password, password_field(&e)) {
                (true, Some(f)) => Some(copy_value(&f.value)?),
                _ => None,
            };
            if username.is_none() && password.is_none() {
                return Err(CoreError::NotFound);
            }
            Ok(FillValues { username, password })
        })
    }

    /// Add an OS-verified app identity to a live, unconflicted entry through
    /// the ordinary edit path. Idempotent when the identical link exists.
    pub fn link_app(
        &self,
        entry: EntryHandle,
        app: &AppIdentity,
    ) -> Result<EntryHandle, CoreError> {
        let url = app.to_url();
        let mut draft = self.edit_entry(entry)?;
        let requester = Requester::App(app.clone());
        if identifies(draft.entry(), &requester) {
            return Ok(entry);
        }
        draft.add_field(
            APP_FIELD_NAME,
            FieldKind::Url,
            FieldValue::text(&url).map_err(|_| CoreError::InvalidInput)?,
        )?;
        self.save_entry(draft)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::platform::autofill::{FillRequest, TrustedBrowser};
    use crate::testutil::{Env, add_entry, kdf};

    const SIGNER: [u8; 32] = [7; 32];
    const BROWSER: &[TrustedBrowser] = &[TrustedBrowser {
        package: "org.example.browser",
        signers: &[[9; 32]],
    }];
    fn roles() -> Roles {
        Roles {
            username: true,
            password: true,
        }
    }
    fn app_request(package: &str) -> FillRequest {
        FillRequest::new(package, &SIGNER, None, None, roles()).unwrap()
    }
    fn web_request(host: &str) -> Requester {
        FillRequest::new(
            "org.example.browser",
            &[9; 32],
            Some("https"),
            Some(host),
            roles(),
        )
        .unwrap()
        .requester(BROWSER)
    }
    fn add_url(s: &Session, e: EntryHandle, url: &str) {
        let mut d = s.edit_entry(e).unwrap();
        d.add_field("Website", FieldKind::Url, FieldValue::text(url).unwrap())
            .unwrap();
        s.save_entry(d).unwrap();
    }

    #[test]
    fn autofill_candidates_match_identity_not_titles_and_release_chosen_values() {
        let env = Env::new();
        let s = env.unlock();
        let root = s.root().unwrap();
        // A title or URL substring naming the service never makes a candidate.
        let spoof = add_entry(&s, root, "bank.example com.bank.app");
        add_url(&s, spoof, "https://bank.example.evil.test/");
        let bank = add_entry(&s, root, "Bank");
        add_url(&s, bank, "https://bank.example/login");
        assert!(
            s.autofill_candidates(&web_request("evil.test"))
                .unwrap()
                .is_empty()
        );
        let found = s.autofill_candidates(&web_request("bank.example")).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].title.expose(), "Bank");
        assert_eq!(found[0].username.as_ref().unwrap().expose(), "alice");
        assert!(!found[0].conflicted);
        let values = s
            .autofill_values(&web_request("bank.example"), found[0].key(), roles())
            .unwrap();
        assert_eq!(values.username.unwrap().expose_secret(), b"alice");
        assert_eq!(values.password.unwrap().expose_secret(), b"hunter2");
        // Only requested roles are returned.
        let only = s
            .autofill_values(
                &web_request("bank.example"),
                found[0].key(),
                Roles {
                    username: false,
                    password: true,
                },
            )
            .unwrap();
        assert!(only.username.is_none() && only.password.is_some());
        // A different requester cannot redeem the candidate.
        assert!(matches!(
            s.autofill_values(&web_request("evil.test"), found[0].key(), roles()),
            Err(CoreError::NotAllowed)
        ));
        // An untrusted app claiming the origin is an app request: no web match.
        let claimed = FillRequest::new(
            "com.evil",
            &SIGNER,
            Some("https"),
            Some("bank.example"),
            roles(),
        )
        .unwrap();
        assert!(
            s.autofill_candidates(&claimed.requester(BROWSER))
                .unwrap()
                .is_empty()
        );
        assert_eq!(format!("{:?}", found[0]), "FillCandidate(<redacted>)");
        assert_eq!(
            format!("{values_dbg:?}", values_dbg = only),
            "FillValues(<redacted>)"
        );

        // After an edit the old head is stale and releases nothing.
        add_url(&s, bank, "https://other.example");
        assert!(matches!(
            s.autofill_values(&web_request("bank.example"), found[0].key(), roles()),
            Err(CoreError::StaleHandle)
        ));
        // Trashed entries are not offered.
        s.delete(crate::ItemHandle::Entry(bank), false).unwrap();
        assert!(
            s.autofill_candidates(&web_request("bank.example"))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn autofill_link_app_requires_exact_signers_and_is_idempotent() {
        let env = Env::new();
        let s = env.unlock();
        let root = s.root().unwrap();
        let e = add_entry(&s, root, "Bank");
        let request = app_request("com.bank.app");
        let requester = request.requester(&[]);
        assert!(s.autofill_candidates(&requester).unwrap().is_empty());
        let e = s.link_app(e, &request.app).unwrap();
        assert_eq!(s.link_app(e, &request.app).unwrap(), e);
        let detail = s.entry(e).unwrap();
        assert_eq!(
            detail
                .fields
                .iter()
                .filter(|f| f.name.expose() == APP_FIELD_NAME)
                .count(),
            1
        );
        assert_eq!(s.autofill_candidates(&requester).unwrap().len(), 1);
        // Same package, other signer: no candidate.
        let other = FillRequest::new("com.bank.app", &[8; 32], None, None, roles()).unwrap();
        assert!(
            s.autofill_candidates(&other.requester(&[]))
                .unwrap()
                .is_empty()
        );
        // Locked sessions release nothing.
        s.lock();
        assert!(s.autofill_candidates(&requester).is_err());
        assert!(s.link_app(e, &request.app).is_err());
    }

    fn set_password(s: &Session, e: EntryHandle, value: &str) {
        let mut d = s.edit_entry(e).unwrap();
        for f in &mut d.entry_mut().fields {
            if f.name.expose() == "Password" {
                f.value = FieldValue::text(value).unwrap();
            }
        }
        s.save_entry(d).unwrap();
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn autofill_conflicted_entry_offers_each_head_and_releases_only_the_choice() {
        use crate::testutil::{PASSWORD, TestDir, pw};
        use qv_store::{AnchorDir, ArchiveScope, VaultFile};
        let env = Env::new();
        let s = env.unlock_with(Some(env.snapshot_policy()));
        let e = add_entry(&s, s.root().unwrap(), "Bank");
        add_url(&s, e, "https://bank.example");
        // Branch the vault, edit both sides, and merge: two heads.
        let path = env.dir.path().join("remote.qvault");
        s.read(|ctx| {
            let mut bytes = Vec::new();
            let now = ctx.now();
            ctx.open.vault.write_archive(&mut bytes, now, &|| false)?;
            let h = ctx.open.vault.header();
            VaultFile::create_from_archive(
                &path,
                &mut std::io::Cursor::new(bytes),
                ArchiveScope::new(h.vault_id, h.key_generation),
                ctx.open.vault.vault_key(),
                &AnchorDir::open(&env.anchors)?,
                &|| false,
            )?;
            Ok(())
        })
        .unwrap();
        let remote = {
            let _k = kdf();
            env.core().unlock(&path, &pw(PASSWORD), None).unwrap()
        };
        let remote_entry = remote.find_id(&e.id_hex(), false).unwrap();
        let crate::ItemHandle::Entry(remote_entry) = remote_entry[0] else {
            unreachable!()
        };
        set_password(&s, e, "local-secret");
        set_password(&remote, remote_entry, "remote-secret");
        let dir = TestDir::new();
        let r = remote.export_archive(dir.path(), false, None).unwrap();
        let incoming = dir.path().join(format!("{}.qvsnap", r.archive_id));
        assert_eq!(
            s.merge_archive(&incoming, false, None).unwrap().conflicts,
            1
        );

        let requester = web_request("bank.example");
        let found = s.autofill_candidates(&requester).unwrap();
        assert_eq!(found.len(), 2);
        assert!(found.iter().all(|c| c.conflicted));
        assert!(found[0].key() != found[1].key());
        let mut released: Vec<Vec<u8>> = found
            .iter()
            .map(|c| {
                s.autofill_values(&requester, c.key(), roles())
                    .unwrap()
                    .password
                    .unwrap()
                    .expose_secret()
                    .to_vec()
            })
            .collect();
        released.sort();
        assert_eq!(
            released,
            [b"local-secret".to_vec(), b"remote-secret".to_vec()]
        );
        // A conflicted entry cannot be linked until resolved.
        assert!(s.link_app(e, &app_request("com.bank.app").app).is_err());
    }
}
