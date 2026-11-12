// SPDX-License-Identifier: AGPL-3.0-or-later

//! Addressing entries and groups (spec 0011 §2).
//!
//! - **Path:** `Group/Subgroup/Title`, relative to the root group. A
//!   leading `/` is allowed, and an empty path or `/` alone names the root.
//!   In a name, `\/` is a slash and `\\` a backslash; any other `\` escape,
//!   and an empty segment (`a//b`), is a usage error (exit 2). A trailing
//!   `/` names a group. Output paths use the same escaping, so they can be
//!   pasted back.
//! - **ID:** `@` and 6 to 32 hex digits, an unambiguous prefix of the
//!   item's ID.
//! - Names match exactly (case-sensitive). Titles need not be unique: a
//!   path or prefix that matches several items is exit 5, listing the
//!   matches with their IDs. Trashed items never match here (0011 §2.4).
//!   Recovered entries (0003 §4.2) are in no group, so only `@id` reaches
//!   them.

use qv_core::{EntryHandle, GroupHandle, ItemHandle, Session};
use zeroize::Zeroizing;

use crate::exit::{AMBIGUOUS, CliError, NOT_FOUND};
use crate::out::escape_str;

/// What an address must name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Want {
    Any,
    Entry,
    Group,
}

/// A parsed path: its segments (unescaped) and whether it ended with `/`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ParsedPath {
    pub(crate) segments: Vec<Zeroizing<String>>,
    pub(crate) trailing_slash: bool,
}

/// Splits a path into unescaped segments.
pub(crate) fn parse_path(s: &str) -> Result<ParsedPath, CliError> {
    let body = s.strip_prefix('/').unwrap_or(s);
    let mut segments = Vec::new();
    let mut cur = Zeroizing::new(String::new());
    let mut chars = body.chars();
    let mut trailing_slash = false;
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next() {
                Some('/') => cur.push('/'),
                Some('\\') => cur.push('\\'),
                _ => {
                    return Err(CliError::usage(
                        "invalid path: use \\/ for a slash and \\\\ for a backslash in a name",
                    ));
                }
            },
            '/' => {
                if cur.is_empty() {
                    return Err(CliError::usage("invalid path: empty name between slashes"));
                }
                segments.push(core::mem::replace(&mut cur, Zeroizing::new(String::new())));
                trailing_slash = true;
            }
            c => {
                trailing_slash = false;
                cur.push(c);
            }
        }
    }
    if !cur.is_empty() {
        segments.push(cur);
    }
    Ok(ParsedPath {
        segments,
        trailing_slash,
    })
}

/// A name with `\` → `\\` and `/` → `\/`.
pub(crate) fn path_escape(name: &str) -> Zeroizing<String> {
    let mut s = Zeroizing::new(String::with_capacity(name.len().saturating_mul(2)));
    for c in name.chars() {
        match c {
            '\\' => s.push_str("\\\\"),
            '/' => s.push_str("\\/"),
            c => s.push(c),
        }
    }
    s
}

/// A revision only; paths decode one component on demand and never cache names.
pub(crate) struct Paths<'a> {
    session: &'a Session,
    revision: u64,
}
impl<'a> Paths<'a> {
    pub(crate) fn walk(s: &'a Session) -> Result<Self, CliError> {
        Ok(Self {
            session: s,
            revision: s.view_revision()?,
        })
    }
    pub(crate) fn check(&self) -> Result<(), CliError> {
        crate::signals::check()?;
        if self.session.view_revision()? != self.revision {
            return Err(qv_core::CoreError::StaleHandle.into());
        }
        Ok(())
    }
    pub(crate) fn revision(&self) -> u64 {
        self.revision
    }
    pub(crate) fn human(
        &self,
        out: &mut crate::out::Out,
        item: ItemHandle,
    ) -> Result<bool, CliError> {
        self.parts(item, |s| {
            out.path(s);
            out.flush()
        })
    }
    pub(crate) fn json(
        &self,
        j: &mut crate::json::Json<'_>,
        item: ItemHandle,
    ) -> Result<(), CliError> {
        if self.session.item_path(item, self.revision)?.is_none() {
            j.null();
            return Ok(());
        }
        j.string_parts(|out| {
            self.parts(item, |s| {
                out.json_piece(s.as_bytes());
                out.flush()
            })?;
            Ok(())
        })
    }
    fn parts(
        &self,
        item: ItemHandle,
        mut write: impl FnMut(&str) -> Result<(), CliError>,
    ) -> Result<bool, CliError> {
        let Some(mut path) = self.session.item_path(item, self.revision)? else {
            return Ok(false);
        };
        let mut nonempty = false;
        while let Some(name) = self.session.path_next(&mut path)? {
            crate::signals::check()?;
            if nonempty {
                write("/")?;
            }
            let escaped = path_escape(name.expose());
            write(&escaped)?;
            nonempty |= !escaped.is_empty();
        }
        Ok(true)
    }
    #[cfg(test)]
    fn get(&self, item: ItemHandle) -> Option<Zeroizing<String>> {
        let mut path = Zeroizing::new(String::new());
        self.parts(item, |s| {
            path.push_str(s);
            Ok(())
        })
        .ok()?
        .then_some(path)
    }
}

fn not_found(addr: &str) -> CliError {
    CliError::new(NOT_FOUND, format!("not found: {}", escape_str(addr)))
}

fn ambiguous(addr: &str, matches: &[ItemHandle]) -> CliError {
    let mut msg = format!(
        "{} matches {} items; use one of these IDs:",
        escape_str(addr),
        matches.len()
    );
    for m in matches {
        let kind = match m {
            ItemHandle::Entry(_) => "entry",
            ItemHandle::Group(_) => "group",
        };
        msg.push_str(&format!("\n  @{}  {kind}", m.id_hex()));
    }
    CliError::new(AMBIGUOUS, msg)
}

/// Exact names from one revision; only matching handles accumulate.
pub(crate) fn named(
    s: &Session,
    group: GroupHandle,
    name: &str,
    want: Want,
    revision: u64,
) -> Result<Vec<ItemHandle>, CliError> {
    let mut hits = Vec::new();
    let mut cursor = None;
    loop {
        let page = s.list_page(
            group,
            cursor,
            qv_core::PageLimit::default(),
            &crate::signals::token(),
        )?;
        if page.revision != revision {
            return Err(qv_core::CoreError::StaleHandle.into());
        }
        for hit in page.items {
            let (item, matches) = match hit {
                qv_core::SearchHit::Group(g) => {
                    (ItemHandle::Group(g.handle), g.name.expose() == name)
                }
                qv_core::SearchHit::Entry(e) => {
                    (ItemHandle::Entry(e.handle), e.title.expose() == name)
                }
            };
            if matches && wanted(&item, want) {
                hits.push(item);
            }
        }
        cursor = page.next;
        if cursor.is_none() {
            break;
        }
    }
    Ok(hits)
}

fn wanted(item: &ItemHandle, want: Want) -> bool {
    matches!(
        (item, want),
        (_, Want::Any) | (ItemHandle::Entry(_), Want::Entry) | (ItemHandle::Group(_), Want::Group)
    )
}

/// Resolves `addr` to one item of the wanted kind.
pub(crate) fn resolve(s: &Session, addr: &str, want: Want) -> Result<ItemHandle, CliError> {
    if let Some(prefix) = addr.strip_prefix('@') {
        let found: Vec<ItemHandle> = match s.find_id(prefix, false) {
            Ok(v) => v.into_iter().filter(|i| wanted(i, want)).collect(),
            Err(qv_core::CoreError::InvalidInput) => {
                return Err(CliError::usage("an @id needs 6 to 32 hex digits"));
            }
            Err(e) => return Err(e.into()),
        };
        return match found.as_slice() {
            [one] => Ok(*one),
            [] => Err(not_found(addr)),
            many => Err(ambiguous(addr, many)),
        };
    }
    let parsed = parse_path(addr)?;
    let root = s.root()?;
    let Some((last, parents)) = parsed.segments.split_last() else {
        return match want {
            Want::Group | Want::Any => Ok(ItemHandle::Group(root)),
            Want::Entry => Err(not_found(addr)),
        };
    };
    if parsed.trailing_slash && want == Want::Entry {
        return Err(not_found(addr));
    }
    let revision = s.view_revision()?;
    let mut group = root;
    for seg in parents {
        let hits = named(s, group, seg, Want::Group, revision)?;
        group = match hits.as_slice() {
            [ItemHandle::Group(one)] => *one,
            [] => return Err(not_found(addr)),
            many => return Err(ambiguous(addr, many)),
        };
    }
    let want = if parsed.trailing_slash {
        Want::Group
    } else {
        want
    };
    let hits = named(s, group, last, want, revision)?;
    match hits.as_slice() {
        [one] => Ok(*one),
        [] => Err(not_found(addr)),
        many => Err(ambiguous(addr, many)),
    }
}

/// Resolves an entry address.
pub(crate) fn entry(s: &Session, addr: &str) -> Result<EntryHandle, CliError> {
    match resolve(s, addr, Want::Entry)? {
        ItemHandle::Entry(e) => Ok(e),
        ItemHandle::Group(_) => Err(not_found(addr)),
    }
}

/// Resolves a group address.
pub(crate) fn group(s: &Session, addr: &str) -> Result<GroupHandle, CliError> {
    match resolve(s, addr, Want::Group)? {
        ItemHandle::Group(g) => Ok(g),
        ItemHandle::Entry(_) => Err(not_found(addr)),
    }
}

#[cfg(test)]
mod tests {

    use qv_core::{AnchorDir, Core, CoreConfig, MasterPassword};

    use super::*;

    fn segs(s: &str) -> Vec<String> {
        parse_path(s)
            .unwrap()
            .segments
            .iter()
            .map(|x| x.as_str().to_owned())
            .collect()
    }

    #[test]
    fn address_parse() {
        assert_eq!(segs("Work/Mail/Login"), ["Work", "Mail", "Login"]);
        assert_eq!(segs("/Work/"), ["Work"]);
        assert!(parse_path("Work/").unwrap().trailing_slash);
        assert!(!parse_path("Work").unwrap().trailing_slash);
        assert_eq!(segs("a\\/b/c\\\\d"), ["a/b", "c\\d"]);
        assert!(segs("").is_empty());
        assert!(segs("/").is_empty());
        for bad in ["a//b", "a\\x", "a\\"] {
            assert_eq!(parse_path(bad).unwrap_err().code, 2, "{bad}");
        }
        assert_eq!(path_escape("a/b\\c").as_str(), "a\\/b\\\\c");
        // Round trip.
        let name = "x/y\\z";
        assert_eq!(segs(&path_escape(name)), [name]);
    }

    struct Fixture {
        dir: std::path::PathBuf,
        session: Session,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn fixture() -> Fixture {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("qv-cli-address-{}-{n}", std::process::id()));
        qv_core::create_private_dirs(&dir).unwrap();
        let core = Core::new(CoreConfig::new(
            AnchorDir::open(&dir.join("anchors")).unwrap(),
        ));
        let pw = MasterPassword::from_utf8(b"address test password").unwrap();
        let session = core
            .create(&dir.join("v.qvault"), &pw, "A")
            .unwrap()
            .session;
        Fixture { dir, session }
    }

    fn group_in(s: &Session, parent: GroupHandle, name: &str) -> GroupHandle {
        let d = s.new_group(parent, name).unwrap();
        s.save_group(d).unwrap()
    }

    fn entry_in(s: &Session, g: GroupHandle, title: &str) -> EntryHandle {
        let d = s.new_entry(g, "login", title).unwrap();
        s.save_entry(d).unwrap()
    }

    #[test]
    fn address_resolve() {
        let f = fixture();
        let s = &f.session;
        let root = s.root().unwrap();
        let work = group_in(s, root, "Work");
        let slash = group_in(s, work, "a/b");
        let mail = entry_in(s, slash, "Mail\\box");
        let dup1 = entry_in(s, work, "Dup");
        let dup2 = entry_in(s, work, "Dup");
        let gone = entry_in(s, work, "Gone");
        s.delete(ItemHandle::Entry(gone), false).unwrap();
        let both = entry_in(s, root, "Work");

        assert_eq!(group(s, "").unwrap(), root);
        assert_eq!(group(s, "/").unwrap(), root);
        assert_eq!(group(s, "Work").unwrap(), work);
        assert_eq!(group(s, "Work/").unwrap(), work);
        assert_eq!(group(s, "Work/a\\/b").unwrap(), slash);
        assert_eq!(entry(s, "Work/a\\/b/Mail\\\\box").unwrap(), mail);
        assert_eq!(entry(s, "/Work/a\\/b/Mail\\\\box").unwrap(), mail);
        // An entry and a group share the name "Work"; the kind decides.
        assert_eq!(entry(s, "Work").unwrap(), both);
        assert_eq!(entry(s, "Work/").unwrap_err().code, 4);

        let e = entry(s, "Work/Dup").unwrap_err();
        assert_eq!(e.code, 5);
        assert!(e.message.contains(&dup1.id_hex()) && e.message.contains(&dup2.id_hex()));
        assert!(e.message.contains("Work/Dup"));

        assert_eq!(
            entry(s, &format!("@{}", &mail.id_hex()[..6])).unwrap(),
            mail
        );
        assert_eq!(group(s, &format!("@{}", work.id_hex())).unwrap(), work);
        assert_eq!(
            entry(s, &format!("@{}", &work.id_hex()[..8]))
                .unwrap_err()
                .code,
            4
        );
        assert_eq!(entry(s, "@abc").unwrap_err().code, 2);
        assert_eq!(entry(s, "@zzzzzz").unwrap_err().code, 2);

        assert_eq!(entry(s, "Nope").unwrap_err().code, 4);
        assert_eq!(entry(s, "Work/Nope/X").unwrap_err().code, 4);
        assert_eq!(entry(s, "Work/Gone").unwrap_err().code, 4);
        assert_eq!(
            entry(s, &format!("@{}", gone.id_hex())).unwrap_err().code,
            4
        );
        assert_eq!(group(s, "Work/Dup").unwrap_err().code, 4);

        let blank = group_in(s, root, "");
        let below_blank = entry_in(s, blank, "Below");
        let paths = Paths::walk(s).unwrap();
        // Preserve the previous join behavior for a leading empty name.
        assert_eq!(
            paths.get(ItemHandle::Entry(below_blank)).unwrap().as_str(),
            "Below"
        );
        assert_eq!(
            paths
                .get(ItemHandle::Group(root))
                .as_deref()
                .map(String::as_str),
            Some("")
        );
        assert_eq!(
            paths
                .get(ItemHandle::Entry(mail))
                .as_deref()
                .map(String::as_str),
            Some("Work/a\\/b/Mail\\\\box")
        );
        assert_eq!(paths.get(ItemHandle::Entry(gone)), None);
    }

    #[test]
    fn deep_listing_uses_ids_per_ancestor_and_one_page() {
        let f = fixture();
        let root = f.session.root().unwrap();
        let depth = 50_000;
        let mut calls = 0;
        let mut emitted = 0;
        crate::cmd::ls::visit(
            root,
            true,
            |_, after| {
                if after.is_some() {
                    return Ok(Vec::new());
                }
                calls += 1;
                if calls >= depth {
                    return Ok(Vec::new());
                }
                Ok(vec![qv_core::SearchHit::Group(qv_core::GroupSummary {
                    handle: root,
                    name: qv_core::Text::new("x").unwrap(),
                    icon: None,
                    order: qv_core::Text::new("").unwrap(),
                    repaired: false,
                    conflict: false,
                    entries: 0,
                })])
            },
            |_| {
                emitted += 1;
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(calls, depth);
        assert_eq!(emitted, depth - 1);
    }

    #[test]
    fn iterative_listing_preserves_branching_order_and_errors() {
        let f = fixture();
        let s = &f.session;
        let root = s.root().unwrap();
        let a = group_in(s, root, "A");
        let b = group_in(s, root, "B");
        let c = group_in(s, a, "C");
        let root_entry = entry_in(s, root, "root");
        let a_entry = entry_in(s, a, "a");
        let b_entry = entry_in(s, b, "b");
        let c_entry = entry_in(s, c, "c");
        let revision = s.view_revision().unwrap();
        let source = |g, after: Option<ItemHandle>| {
            let cursor = after.map(|a| s.list_resume(g, a, revision)).transpose()?;
            Ok::<_, CliError>(
                s.list_page(
                    g,
                    cursor,
                    qv_core::PageLimit::default(),
                    &qv_core::CancelToken::new(),
                )?
                .items,
            )
        };
        let mut groups = Vec::new();
        let mut entries = Vec::new();
        crate::cmd::ls::visit(root, true, source, |hit| {
            match hit {
                qv_core::SearchHit::Group(g) => groups.push(g.handle),
                qv_core::SearchHit::Entry(e) => entries.push(e.handle),
            };
            Ok(())
        })
        .unwrap();
        assert_eq!(groups, [a, c, b]);
        assert_eq!(entries, [c_entry, a_entry, b_entry, root_entry]);
        groups.clear();
        entries.clear();
        crate::cmd::ls::visit(root, false, source, |hit| {
            match hit {
                qv_core::SearchHit::Group(g) => groups.push(g.handle),
                qv_core::SearchHit::Entry(e) => entries.push(e.handle),
            };
            Ok(())
        })
        .unwrap();
        assert_eq!(groups, [a, b]);
        assert_eq!(entries, [root_entry]);
        let error = crate::cmd::ls::visit(
            root,
            true,
            |g, after| {
                if g == c {
                    Err(CliError::new(crate::exit::LIMIT, "test limit"))
                } else {
                    source(g, after)
                }
            },
            |_| Ok(()),
        )
        .unwrap_err();
        assert_eq!(error.code, crate::exit::LIMIT);
    }
}
