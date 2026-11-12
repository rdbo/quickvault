// SPDX-License-Identifier: AGPL-3.0-or-later

//! Windows security descriptors as bytes: SID and DACL parsing, the private
//! file rules of spec 0009 §5.1 and the protected owner-only descriptor
//! used for new files. Pure Rust on every target, so the rules are tested
//! on Linux too; only reading and applying descriptors needs Win32.
//!
//! Formats follow [MS-DTYP] §2.4.2 (SID), §2.4.4 (ACE), §2.4.5 (ACL) and
//! §2.4.6 (self-relative security descriptor). Every length is checked
//! before use and anything unexpected fails closed.

/// A SID in its binary form ([MS-DTYP] §2.4.2.2).
#[derive(Clone, PartialEq, Eq)]
pub struct Sid(Vec<u8>);

impl core::fmt::Debug for Sid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // A SID names an account; it is not secret but not useful in logs.
        f.write_str("Sid(..)")
    }
}

const MAX_SUB_AUTHORITIES: usize = 15;

impl Sid {
    /// Parses exactly one SID from the start of `bytes`, returning it and
    /// its length. `None` unless revision 1 with at most 15 sub-authorities
    /// that fit in `bytes`.
    pub fn parse_prefix(bytes: &[u8]) -> Option<(Self, usize)> {
        let (&revision, rest) = bytes.split_first()?;
        let &count = rest.first()?;
        let count = usize::from(count);
        if revision != 1 || count > MAX_SUB_AUTHORITIES {
            return None;
        }
        let len = 8 + 4 * count;
        let sid = bytes.get(..len)?;
        Some((Self(sid.to_vec()), len))
    }

    /// Parses `bytes` as exactly one SID.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        match Self::parse_prefix(bytes) {
            Some((sid, len)) if len == bytes.len() => Some(sid),
            _ => None,
        }
    }

    /// The binary form.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    fn well_known(authority: u8, subs: &[u32]) -> Self {
        let mut b = vec![1, subs.len() as u8, 0, 0, 0, 0, 0, authority];
        for s in subs {
            b.extend_from_slice(&s.to_le_bytes());
        }
        Self(b)
    }

    /// S-1-5-18, LocalSystem.
    pub fn local_system() -> Self {
        Self::well_known(5, &[18])
    }

    /// S-1-5-32-544, BUILTIN\Administrators.
    pub fn administrators() -> Self {
        Self::well_known(5, &[32, 544])
    }

    /// NT SERVICE\TrustedInstaller, owner of system folders such as `C:\`.
    pub fn trusted_installer() -> Self {
        Self::well_known(
            5,
            &[
                80,
                956_008_885,
                3_418_522_649,
                1_831_038_044,
                1_853_292_631,
                2_271_478_464,
            ],
        )
    }

    /// S-1-1-0, Everyone (test fixtures only).
    pub fn everyone() -> Self {
        Self::well_known(1, &[0])
    }

    /// S-1-3-4, OWNER RIGHTS: applies to the object's owner.
    pub fn owner_rights() -> Self {
        Self::well_known(3, &[4])
    }
}

/// Which private-file rule an object must meet (spec 0009 §5.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rule {
    /// A vault file or other private file: only trusted SIDs have access.
    OwnerOnly,
    /// A directory others must not modify (anchor, snapshot, state dirs).
    NoForeignWrite,
    /// A vault's parent: no foreign write, and nothing that new files there
    /// would inherit grants another SID access (SQLite's `-journal` is
    /// created with inherited security).
    VaultParent,
    /// An ancestor of an explicitly chosen user file: no other SID may
    /// delete, rename or re-permission it or its entries (adding new names
    /// cannot replace an existing component).
    NoForeignReplace,
}

/// Rights that let another principal add, remove, rename or re-permission
/// entries or the object itself.
pub const WRITE_CLASS: u32 = 0x0000_0002 // FILE_ADD_FILE / FILE_WRITE_DATA
    | 0x0000_0004 // FILE_ADD_SUBDIRECTORY / FILE_APPEND_DATA
    | 0x0000_0040 // FILE_DELETE_CHILD
    | 0x0001_0000 // DELETE
    | 0x0004_0000 // WRITE_DAC
    | 0x0008_0000 // WRITE_OWNER
    | 0x0200_0000 // MAXIMUM_ALLOWED
    | 0x1000_0000 // GENERIC_ALL
    | 0x4000_0000; // GENERIC_WRITE

/// Rights that let another principal remove or replace an existing entry.
pub const REPLACE_CLASS: u32 = 0x0000_0040 // FILE_DELETE_CHILD
    | 0x0001_0000 // DELETE
    | 0x0004_0000 // WRITE_DAC
    | 0x0008_0000 // WRITE_OWNER
    | 0x0200_0000 // MAXIMUM_ALLOWED
    | 0x1000_0000; // GENERIC_ALL

/// Full access to a file or directory (FILE_ALL_ACCESS).
pub const FILE_ALL_ACCESS: u32 = 0x001F_01FF;

const ACCESS_ALLOWED: u8 = 0;
const ACCESS_DENIED: u8 = 1;
const ACCESS_ALLOWED_CALLBACK: u8 = 9;
const ACCESS_DENIED_OBJECT: u8 = 6;
const ACCESS_DENIED_CALLBACK: u8 = 10;
const ACCESS_DENIED_CALLBACK_OBJECT: u8 = 12;
const OBJECT_INHERIT: u8 = 0x01;
const CONTAINER_INHERIT: u8 = 0x02;
const INHERIT_ONLY: u8 = 0x08;

/// One ACE as far as the rules need it.
#[derive(Debug, PartialEq, Eq)]
enum Ace {
    /// Restricts access only; never makes an object less private.
    Deny,
    /// Grants `mask` to `sid` (`flags` are the ACE flags).
    Allow { flags: u8, mask: u32, sid: Sid },
}

/// Parses a binary ACL ([MS-DTYP] §2.4.5). `None` if malformed or if any
/// ACE is an allow type whose trustee cannot be read (object ACEs).
fn parse_acl(acl: &[u8]) -> Option<Vec<Ace>> {
    let header = acl.get(..8)?;
    if !matches!(header[0], 2 | 4) {
        return None;
    }
    let size = usize::from(u16::from_le_bytes([header[2], header[3]]));
    let count = usize::from(u16::from_le_bytes([header[4], header[5]]));
    let body = acl.get(8..size)?;
    let mut aces = Vec::with_capacity(count.min(body.len() / 4));
    let mut at = 0;
    for _ in 0..count {
        let h = body.get(at..at + 4)?;
        let (kind, flags) = (h[0], h[1]);
        let ace_size = usize::from(u16::from_le_bytes([h[2], h[3]]));
        if ace_size < 4 || !ace_size.is_multiple_of(4) {
            return None;
        }
        let ace = body.get(at..at + ace_size)?;
        aces.push(match kind {
            ACCESS_DENIED
            | ACCESS_DENIED_OBJECT
            | ACCESS_DENIED_CALLBACK
            | ACCESS_DENIED_CALLBACK_OBJECT => Ace::Deny,
            ACCESS_ALLOWED | ACCESS_ALLOWED_CALLBACK => {
                let mask = u32::from_le_bytes(ace.get(4..8)?.try_into().ok()?);
                // Callback ACEs carry application data after the SID.
                let (sid, len) = Sid::parse_prefix(ace.get(8..)?)?;
                if kind == ACCESS_ALLOWED && 8 + len != ace_size {
                    return None;
                }
                Ace::Allow { flags, mask, sid }
            }
            // Object, audit, label and unknown types: fail closed.
            _ => return None,
        });
        at += ace_size;
    }
    Some(aces)
}

/// Whether an object with this `owner` and DACL (`None` = NULL DACL, which
/// grants everyone everything) meets `rule` for the current `user`.
/// Trusted SIDs are `user`, LocalSystem, Administrators, TrustedInstaller
/// and, as the owner is required to be trusted, OWNER RIGHTS.
pub fn meets(owner: &Sid, dacl: Option<&[u8]>, user: &Sid, rule: Rule) -> bool {
    let system = Sid::local_system();
    let admins = Sid::administrators();
    let installer = Sid::trusted_installer();
    let owner_rights = Sid::owner_rights();
    let principal = |s: &Sid| s == user || *s == system || *s == admins || *s == installer;
    let trusted = |s: &Sid| principal(s) || *s == owner_rights;
    if !principal(owner) {
        return false;
    }
    let Some(aces) = dacl.and_then(parse_acl) else {
        return false;
    };
    aces.iter().all(|ace| match ace {
        Ace::Deny => true,
        Ace::Allow { sid, .. } if trusted(sid) => true,
        Ace::Allow { flags, mask, .. } => {
            let applies = flags & INHERIT_ONLY == 0;
            match rule {
                Rule::OwnerOnly => !applies || *mask == 0,
                Rule::NoForeignWrite => !applies || mask & WRITE_CLASS == 0,
                Rule::NoForeignReplace => !applies || mask & REPLACE_CLASS == 0,
                Rule::VaultParent => {
                    (!applies || mask & WRITE_CLASS == 0)
                        && (flags & OBJECT_INHERIT == 0 || *mask == 0)
                }
            }
        }
    })
}

/// One allow ACE for [`descriptor`].
#[derive(Clone, Copy, Debug)]
pub struct Grant<'a> {
    /// Trustee.
    pub sid: &'a Sid,
    /// Access mask.
    pub mask: u32,
    /// Whether new files and subdirectories inherit it.
    pub inherit: bool,
}

/// A self-relative security descriptor ([MS-DTYP] §2.4.6) owned by `user`
/// with a protected DACL holding one full-access ACE for `user`;
/// `inherit` makes the ACE inherit to files and subdirectories. Returned
/// as 32-bit words so the buffer is suitably aligned for Win32.
pub fn private_descriptor(user: &Sid, inherit: bool) -> Vec<u32> {
    descriptor(
        user,
        &[Grant {
            sid: user,
            mask: FILE_ALL_ACCESS,
            inherit,
        }],
    )
}

/// A self-relative descriptor owned by `owner` with a protected DACL of
/// exactly `grants` (test fixtures model shared folders with extra grants).
pub fn descriptor(owner: &Sid, grants: &[Grant<'_>]) -> Vec<u32> {
    const SELF_RELATIVE: u16 = 0x8000;
    const DACL_PRESENT: u16 = 0x0004;
    const DACL_PROTECTED: u16 = 0x1000;
    let mut acl = Vec::new();
    for g in grants {
        let size = 8 + g.sid.as_bytes().len();
        let flags = if g.inherit {
            OBJECT_INHERIT | CONTAINER_INHERIT
        } else {
            0
        };
        acl.extend_from_slice(&[ACCESS_ALLOWED, flags]);
        acl.extend_from_slice(&(size as u16).to_le_bytes());
        acl.extend_from_slice(&g.mask.to_le_bytes());
        acl.extend_from_slice(g.sid.as_bytes());
    }
    let acl_size = (8 + acl.len()) as u16;
    let mut dacl = vec![2, 0];
    dacl.extend_from_slice(&acl_size.to_le_bytes());
    dacl.extend_from_slice(&(grants.len() as u16).to_le_bytes());
    dacl.extend_from_slice(&[0, 0]);
    dacl.extend_from_slice(&acl);

    let owner_at = 20u32;
    let dacl_at = owner_at + owner.as_bytes().len() as u32;
    let mut sd = vec![1, 0];
    sd.extend_from_slice(&(SELF_RELATIVE | DACL_PRESENT | DACL_PROTECTED).to_le_bytes());
    for offset in [owner_at, 0, 0, dacl_at] {
        sd.extend_from_slice(&offset.to_le_bytes());
    }
    sd.extend_from_slice(owner.as_bytes());
    sd.extend_from_slice(&dacl);
    // SIDs and ACEs are multiples of four bytes, so no padding is needed.
    sd.chunks(4)
        .map(|w| {
            let mut b = [0u8; 4];
            b[..w.len()].copy_from_slice(w);
            u32::from_le_bytes(b)
        })
        .collect()
}

/// Splits a self-relative descriptor into its owner and DACL bytes (test
/// helper and a cross-check of [`descriptor`]).
pub fn split_descriptor(sd: &[u8]) -> Option<(Sid, Option<Vec<u8>>)> {
    let control = u16::from_le_bytes(sd.get(2..4)?.try_into().ok()?);
    let word = |i: usize| -> Option<usize> {
        Some(u32::from_le_bytes(sd.get(i..i + 4)?.try_into().ok()?) as usize)
    };
    let (owner, dacl_at) = (word(4)?, word(16)?);
    let (owner, _) = Sid::parse_prefix(sd.get(owner..)?)?;
    let dacl = if control & 0x0004 == 0 || dacl_at == 0 {
        None
    } else {
        let at = sd.get(dacl_at..)?;
        let size = usize::from(u16::from_le_bytes(at.get(2..4)?.try_into().ok()?));
        Some(at.get(..size)?.to_vec())
    };
    Some((owner, dacl))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn user() -> Sid {
        // S-1-5-21-1-2-3-1001
        Sid::well_known(5, &[21, 1, 2, 3, 1001])
    }
    fn other() -> Sid {
        Sid::well_known(5, &[21, 1, 2, 3, 1002])
    }
    fn bytes(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|w| w.to_le_bytes()).collect()
    }
    fn check(grants: &[(&Sid, u32)], inherit: bool, rule: Rule) -> bool {
        let grants: Vec<Grant<'_>> = grants
            .iter()
            .map(|&(sid, mask)| Grant { sid, mask, inherit })
            .collect();
        let sd = bytes(&descriptor(&user(), &grants));
        let (owner, dacl) = split_descriptor(&sd).unwrap();
        meets(&owner, dacl.as_deref(), &user(), rule)
    }

    #[test]
    fn sid_parsing_is_exact() {
        let u = user();
        assert_eq!(Sid::parse(u.as_bytes()), Some(u.clone()));
        let mut long = u.as_bytes().to_vec();
        long.push(0);
        assert_eq!(Sid::parse(&long), None);
        assert_eq!(Sid::parse(&u.as_bytes()[..9]), None);
        let mut bad = u.as_bytes().to_vec();
        bad[0] = 2;
        assert_eq!(Sid::parse(&bad), None);
        assert_eq!(Sid::parse(&[1, 16, 0, 0, 0, 0, 0, 5]), None);
        assert_eq!(
            Sid::local_system().as_bytes(),
            [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]
        );
        assert_eq!(format!("{:?}", u), "Sid(..)");
    }

    #[test]
    fn private_descriptor_meets_every_rule() {
        let u = user();
        let sd = bytes(&private_descriptor(&u, true));
        let (owner, dacl) = split_descriptor(&sd).unwrap();
        assert_eq!(owner, u);
        for rule in [
            Rule::OwnerOnly,
            Rule::NoForeignWrite,
            Rule::VaultParent,
            Rule::NoForeignReplace,
        ] {
            assert!(meets(&owner, dacl.as_deref(), &u, rule));
        }
        // Control: self-relative, DACL present and protected.
        assert_eq!(u16::from_le_bytes([sd[2], sd[3]]), 0x9004);
    }

    #[test]
    fn foreign_access_is_refused_by_rule() {
        let o = other();
        let e = Sid::everyone();
        let read = 0x0012_0089; // FILE_GENERIC_READ
        let modify = 0x0013_01BF;
        // Foreign read: refused for a private file, fine for directories
        // unless it is inherited by new files in a vault's parent.
        assert!(!check(
            &[(&user(), FILE_ALL_ACCESS), (&e, read)],
            false,
            Rule::OwnerOnly
        ));
        assert!(check(
            &[(&user(), FILE_ALL_ACCESS), (&e, read)],
            false,
            Rule::NoForeignWrite
        ));
        assert!(check(
            &[(&user(), FILE_ALL_ACCESS), (&e, read)],
            false,
            Rule::VaultParent
        ));
        assert!(!check(
            &[(&user(), FILE_ALL_ACCESS), (&e, read)],
            true,
            Rule::VaultParent
        ));
        // Foreign write is refused everywhere.
        for rule in [Rule::OwnerOnly, Rule::NoForeignWrite, Rule::VaultParent] {
            assert!(!check(
                &[(&user(), FILE_ALL_ACCESS), (&o, modify)],
                false,
                rule
            ));
            assert!(!check(&[(&o, 0x0000_0002)], false, rule));
            assert!(!check(&[(&o, 0x4000_0000)], false, rule));
        }
        // Adding names to an ancestor does not replace a component; deleting
        // or re-permissioning does.
        let add = 0x0000_0006; // add file, add subdirectory
        assert!(check(
            &[(&user(), FILE_ALL_ACCESS), (&o, add)],
            false,
            Rule::NoForeignReplace
        ));
        assert!(!check(
            &[(&user(), FILE_ALL_ACCESS), (&o, add)],
            false,
            Rule::NoForeignWrite
        ));
        for m in [0x0000_0040, 0x0001_0000, 0x0004_0000, 0x1000_0000] {
            assert!(!check(&[(&o, m)], false, Rule::NoForeignReplace), "{m:x}");
        }
        // Trusted principals may have any access.
        let sys = Sid::local_system();
        let adm = Sid::administrators();
        assert!(check(
            &[(&sys, FILE_ALL_ACCESS), (&adm, FILE_ALL_ACCESS)],
            true,
            Rule::OwnerOnly
        ));
    }

    #[test]
    fn owner_null_dacl_and_malformed_acls_fail_closed() {
        let u = user();
        let sd = bytes(&private_descriptor(&u, false));
        let (_, dacl) = split_descriptor(&sd).unwrap();
        let dacl = dacl.unwrap();
        // A foreign owner, even with a private DACL.
        assert!(!meets(&other(), Some(&dacl), &u, Rule::NoForeignWrite));
        assert!(meets(
            &Sid::administrators(),
            Some(&dacl),
            &u,
            Rule::OwnerOnly
        ));
        // NULL DACL grants everyone everything.
        assert!(!meets(&u, None, &u, Rule::NoForeignWrite));
        // Truncations and corrupted sizes.
        for cut in 0..dacl.len() {
            let mut d = dacl[..cut].to_vec();
            if d.len() >= 4 {
                d[2..4].copy_from_slice(&(cut as u16).to_le_bytes());
            }
            assert!(!meets(&u, Some(&d), &u, Rule::OwnerOnly), "{cut}");
        }
        let mut odd = dacl.clone();
        odd[10..12].copy_from_slice(&5u16.to_le_bytes()); // ACE size not 4-aligned
        assert!(!meets(&u, Some(&odd), &u, Rule::OwnerOnly));
        let mut object = dacl.clone();
        object[8] = 5; // ACCESS_ALLOWED_OBJECT_ACE: trustee not parsed
        assert!(!meets(&u, Some(&object), &u, Rule::OwnerOnly));
        let mut revision = dacl.clone();
        revision[0] = 3;
        assert!(!meets(&u, Some(&revision), &u, Rule::OwnerOnly));
    }

    #[test]
    fn deny_and_inherit_only_aces_do_not_grant() {
        let u = user();
        let o = other();
        let g = |sid| Grant {
            sid,
            mask: FILE_ALL_ACCESS,
            inherit: false,
        };
        let sd = bytes(&descriptor(&u, &[g(&u), g(&o)]));
        let (owner, dacl) = split_descriptor(&sd).unwrap();
        let mut dacl = dacl.unwrap();
        let second = 8 + 8 + u.as_bytes().len();
        let mut deny = dacl.clone();
        deny[second] = ACCESS_DENIED;
        assert!(meets(&owner, Some(&deny), &u, Rule::OwnerOnly));
        // Inherit-only to directories only: does not apply to this object
        // or to new files.
        dacl[second + 1] = INHERIT_ONLY | CONTAINER_INHERIT;
        assert!(meets(&owner, Some(&dacl), &u, Rule::OwnerOnly));
        assert!(meets(&owner, Some(&dacl), &u, Rule::VaultParent));
        // Inherit-only to files: new journals would grant it.
        dacl[second + 1] = INHERIT_ONLY | OBJECT_INHERIT;
        assert!(!meets(&owner, Some(&dacl), &u, Rule::VaultParent));
        assert!(meets(&owner, Some(&dacl), &u, Rule::NoForeignWrite));
    }
}
