// SPDX-License-Identifier: AGPL-3.0-or-later

//! Snapshot inventory codec and directory evidence (plan 0022 steps 5–6;
//! 0012 §1 row "Hostile SQLite/CBOR" for the inventory parser).

use qv_crypto::{KeyGeneration, VaultId, VaultKey};
use qv_encoding::{Decoder, Encoder};
use qv_model::Timestamp;

use super::*;

fn id(b: u8) -> [u8; 16] {
    let mut v = [b; 16];
    v[6] = (v[6] & 15) | 64;
    v[8] = (v[8] & 63) | 128;
    v
}

fn ones() -> VaultKey {
    // Public BIP-39 encoding vector: all-one entropy.
    VaultKey::from_recovery_phrase(format!("{}vote", "zoo ".repeat(23)).as_bytes()).unwrap()
}

fn vector_rows() -> Vec<InventoryRow> {
    vec![
        InventoryRow {
            archive_id: [0x10; 16],
            generation: KeyGeneration(1),
            created_at: Timestamp(1_700_000_000_000),
            size: 1234,
            sha256: [0xab; 32],
        },
        InventoryRow {
            archive_id: [0x20; 16],
            generation: KeyGeneration(1),
            created_at: Timestamp(1_700_000_360_000),
            size: 99,
            sha256: [0xcd; 32],
        },
    ]
}

fn vector() -> SnapshotInventory {
    SnapshotInventory::sign(VaultId(id(0x22)), KeyGeneration(2), vector_rows(), &ones()).unwrap()
}

fn err(input: &[u8]) -> StoreError {
    SnapshotInventory::decode(input).err().unwrap()
}

/// The top-level `(key, raw value)` pairs of an encoded inventory.
fn fields(input: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut d = Decoder::new(input).unwrap();
    let n = d.map().unwrap();
    (0..n)
        .map(|_| {
            let key = u8::try_from(d.uint().unwrap()).unwrap();
            (key, d.raw_value().unwrap().as_bytes().to_vec())
        })
        .collect()
}

fn reencode(fields: &[(u8, Vec<u8>)]) -> Vec<u8> {
    // Small positive keys and a short map head suffice for these fixtures.
    let mut out = vec![0xa0 | u8::try_from(fields.len()).unwrap()];
    for (k, v) in fields {
        out.push(*k);
        out.extend_from_slice(v);
    }
    out
}

/// A rows array with arbitrary (possibly invalid) rows.
fn rows_value(rows: &[([u8; 16], u64, i64, u64)]) -> Vec<u8> {
    let mut e = Encoder::new();
    e.array(|a| {
        for (archive, generation, created, size) in rows {
            a.array(|x| {
                x.bytes(archive);
                x.uint(*generation);
                x.int(*created);
                x.uint(*size);
                x.bytes(&[0; 32]);
                Ok(())
            })?;
        }
        Ok(())
    })
    .unwrap();
    e.finish().unwrap().to_vec()
}

#[test]
fn snapshot_inventory_independent_vector_and_round_trip() {
    let inventory = vector();
    let encoded = inventory.encode().unwrap();
    assert_eq!(
        encoded.as_slice(),
        include_bytes!("../tests/vectors/snapshot-inventory.cbor")
    );
    let decoded = SnapshotInventory::decode(&encoded)
        .unwrap()
        .verify(VaultId(id(0x22)), KeyGeneration(2), &ones())
        .unwrap();
    assert_eq!(decoded.rows(), vector_rows().as_slice());
    assert_eq!(decoded.encode().unwrap(), encoded);
    assert_eq!(decoded.generation(), KeyGeneration(2));
    // Wrong key, generation or vault.
    for (vault, generation, key) in [
        (
            VaultId(id(0x22)),
            KeyGeneration(2),
            VaultKey::generate().unwrap(),
        ),
        (VaultId(id(0x22)), KeyGeneration(3), ones()),
        (VaultId(id(0x33)), KeyGeneration(2), ones()),
    ] {
        assert_eq!(
            SnapshotInventory::decode(&encoded)
                .unwrap()
                .verify(vault, generation, &key)
                .err(),
            Some(StoreError::Integrity)
        );
    }
    assert_eq!(format!("{inventory:?}"), "SnapshotInventory(2 rows)");
    assert_eq!(
        format!("{:?}", SnapshotInventory::decode(&encoded).unwrap()),
        "UnverifiedInventory(..)"
    );
    assert_eq!(
        file_name(VaultId(id(0x22)), KeyGeneration(2)),
        "inventory-2222222222224222a222222222222222-00000002.qvinv"
    );
}

#[test]
fn snapshot_inventory_every_byte_is_structural_or_authenticated() {
    let encoded = vector().encode().unwrap();
    for end in 0..encoded.len() {
        assert!(SnapshotInventory::decode(&encoded[..end]).is_err());
    }
    for i in 0..encoded.len() {
        let mut changed = encoded.clone();
        changed[i] ^= 1;
        if let Ok(candidate) = SnapshotInventory::decode(&changed) {
            assert!(
                candidate
                    .verify(VaultId(id(0x22)), KeyGeneration(2), &ones())
                    .is_err(),
                "byte {i}"
            );
        }
    }
}

#[test]
fn snapshot_inventory_rejects_bad_shape_bounds_and_rows() {
    let encoded = vector().encode().unwrap();
    let original = fields(&encoded);
    assert_eq!(
        err(&vec![0; MAX_INVENTORY_BYTES + 1]),
        StoreError::LimitExceeded
    );
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert_eq!(err(&trailing), StoreError::Integrity);
    for key in 0..5 {
        let mut f = original.clone();
        f.remove(key);
        assert_eq!(err(&reencode(&f)), StoreError::Integrity, "missing {key}");
        let mut f = original.clone();
        f[key].1 = vec![0xf6];
        assert_eq!(err(&reencode(&f)), StoreError::Integrity, "null {key}");
    }
    let mut f = original.clone();
    f[0].1 = vec![2];
    assert_eq!(err(&reencode(&f)), StoreError::Unsupported);
    let mut f = original.clone();
    f.push((5, vec![0]));
    assert_eq!(err(&reencode(&f)), StoreError::Unsupported);
    // Generation 1 cannot carry earlier generations; a bad vault UUID.
    let mut f = original.clone();
    f[2].1 = vec![1];
    assert_eq!(err(&reencode(&f)), StoreError::Integrity);
    let mut f = original.clone();
    f[1].1[7] = 0; // UUID byte 6: the version nibble
    assert_eq!(err(&reencode(&f)), StoreError::Integrity);
    // Unsorted, duplicate, generation 0 and generation ≥ the inventory's.
    for rows in [
        vec![([0x20; 16], 1, 1, 1), ([0x10; 16], 1, 1, 1)],
        vec![([0x10; 16], 1, 1, 1), ([0x10; 16], 1, 1, 1)],
        vec![([0x10; 16], 0, 1, 1)],
        vec![([0x10; 16], 2, 1, 1)],
    ] {
        let mut f = original.clone();
        f[3].1 = rows_value(&rows);
        assert_eq!(err(&reencode(&f)), StoreError::Integrity);
    }
    // A truncated row array is malformed before any count is trusted; a
    // well-formed array of 4097 rows is refused by the row bound.
    let mut f = original.clone();
    f[3].1 = vec![0x99, 0x10, 0x01];
    assert_eq!(err(&reencode(&f)), StoreError::Integrity);
    let many: Vec<_> = (0..=MAX_INVENTORY_ROWS)
        .map(|i| {
            let mut a = [0; 16];
            a[..8].copy_from_slice(&(i as u64).to_be_bytes());
            (a, 1, 1, 1)
        })
        .collect();
    let mut f = original.clone();
    f[3].1 = rows_value(&many);
    assert_eq!(err(&reencode(&f)), StoreError::LimitExceeded);
    // Wrong row arity and wrong fixed-length fields.
    let mut f = original.clone();
    f[3].1 = vec![0x81, 0x80];
    assert_eq!(err(&reencode(&f)), StoreError::Integrity);
    let mut f = original;
    f[4].1 = vec![0x41, 0];
    assert_eq!(err(&reencode(&f)), StoreError::Integrity);

    // Exactly the row bound is accepted; one more is refused.
    let row = |i: usize| InventoryRow {
        archive_id: {
            let mut a = [0; 16];
            a[..8].copy_from_slice(&(i as u64).to_be_bytes());
            a
        },
        generation: KeyGeneration(1),
        created_at: Timestamp(i as i64),
        size: i as u64,
        sha256: [7; 32],
    };
    let full: Vec<_> = (0..MAX_INVENTORY_ROWS).map(row).collect();
    let signed =
        SnapshotInventory::sign(VaultId(id(0x22)), KeyGeneration(2), full, &ones()).unwrap();
    let bytes = signed.encode().unwrap();
    assert!(bytes.len() <= MAX_INVENTORY_BYTES);
    assert!(SnapshotInventory::decode(&bytes).is_ok());
    let over: Vec<_> = (0..=MAX_INVENTORY_ROWS).map(row).collect();
    assert_eq!(
        SnapshotInventory::sign(VaultId(id(0x22)), KeyGeneration(2), over, &ones()).err(),
        Some(StoreError::LimitExceeded)
    );
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod dir {
    use std::path::Path;

    use super::*;
    use crate::fs::test_dir::{TestDir, write_file};
    use crate::vault::tests::{
        NAME, PASSWORD, anchors as anchor_dir, copy_fixture, kdf, pw, unlock,
    };
    use crate::{SnapshotDir, SnapshotKind, UnlockedVault, VaultFile};

    fn snapshot_dir(d: &TestDir) -> SnapshotDir {
        SnapshotDir::open(&d.join("snapshots")).unwrap()
    }

    fn names(dir: &SnapshotDir) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        v.sort();
        v
    }

    fn sha(path: &Path) -> [u8; 32] {
        qv_crypto::object_hash(
            qv_crypto::ObjectHashProfile::V1,
            &std::fs::read(path).unwrap(),
        )
        .0
    }

    fn snapshot(dir: &SnapshotDir, u: &mut UnlockedVault, kind: SnapshotKind, at: i64) -> String {
        dir.publish(u, kind, Timestamp(at), &|| false)
            .unwrap()
            .archive_id()
            .to_owned()
    }

    fn prepare(u: UnlockedVault) -> crate::PreparedRotation {
        let _k = kdf();
        u.prepare_rotation(&pw("inventory test replacement passphrase"), &|| false)
            .unwrap()
    }

    #[test]
    fn snapshot_inventory_dir_builds_from_authenticated_and_carried_rows() {
        let (d, a, s) = (TestDir::new(), TestDir::new(), TestDir::new());
        let (path, anchors) = copy_fixture(&d, &a, "v.qvault");
        let dir = snapshot_dir(&s);
        let mut u = unlock(&path, &anchors, PASSWORD).unwrap();
        let first = snapshot(&dir, &mut u, SnapshotKind::Ordinary, 1_700_000_000_000);
        let second = snapshot(&dir, &mut u, SnapshotKind::Recovery, 1_700_000_100_000);
        // Ignored: damaged bytes under a snapshot name and another vault's copy.
        write_file(
            &dir.path().join(format!("{}.qvsnap", "ab".repeat(16))),
            b"x",
            0o600,
        );
        let other = {
            let (o, oa) = (TestDir::new(), TestDir::new());
            let _k = kdf();
            let mut v =
                VaultFile::create(&o.join("o.qvault"), &pw(PASSWORD), NAME, &anchor_dir(&oa))
                    .unwrap();
            snapshot(&dir, &mut v, SnapshotKind::Ordinary, 1)
        };
        // Previous rows: one still matching, one changed and one missing.
        let (kept, changed, missing) = ([0x10; 16], [0x20; 16], [0x30; 16]);
        let file = |id: [u8; 16]| dir.path().join(format!("{}.qvsnap", hex(&id)));
        write_file(&file(kept), b"earlier generation", 0o600);
        write_file(&file(changed), b"before", 0o600);
        let row = |id: [u8; 16], bytes: &[u8]| InventoryRow {
            archive_id: id,
            generation: KeyGeneration(1),
            created_at: Timestamp(5),
            size: bytes.len() as u64,
            sha256: qv_crypto::object_hash(qv_crypto::ObjectHashProfile::V1, bytes).0,
        };
        let previous_vk = VaultKey::generate().unwrap();
        let previous = SnapshotInventory::sign(
            u.header().vault_id,
            KeyGeneration(2),
            vec![
                row(kept, b"earlier generation"),
                row(changed, b"before"),
                row(missing, b"gone"),
            ],
            &previous_vk,
        )
        .unwrap();
        write_file(&file(changed), b"after!", 0o600);
        let new_vk = VaultKey::generate().unwrap();
        let before = names(&dir);
        let built = dir
            .build_inventory(
                u.header().vault_id,
                u.header().key_generation,
                u.vault_key(),
                Some(&previous),
                KeyGeneration(3),
                &new_vk,
                &|| false,
            )
            .unwrap();
        let ids: Vec<String> = built
            .rows()
            .iter()
            .map(InventoryRow::archive_id_hex)
            .collect();
        let mut expected = vec![first.clone(), second.clone(), hex(&kept)];
        expected.sort();
        assert_eq!(ids, expected);
        assert!(!ids.contains(&other));
        for r in built.rows() {
            let name = if r.archive_id_hex() == second {
                format!("recover-{second}.qvsnap")
            } else {
                format!("{}.qvsnap", r.archive_id_hex())
            };
            let p = dir.path().join(name);
            assert_eq!(r.sha256, sha(&p));
            assert_eq!(r.size, std::fs::metadata(&p).unwrap().len());
        }
        let first_row = built
            .rows()
            .iter()
            .find(|r| r.archive_id_hex() == first)
            .unwrap();
        assert_eq!(first_row.created_at, Timestamp(1_700_000_000_000));
        assert_eq!(first_row.generation, KeyGeneration(1));
        assert_eq!(names(&dir), before, "building writes nothing");
        // Cancellation fails and writes nothing.
        assert_eq!(
            dir.build_inventory(
                u.header().vault_id,
                u.header().key_generation,
                u.vault_key(),
                None,
                KeyGeneration(2),
                &new_vk,
                &|| true,
            )
            .err(),
            Some(StoreError::Io)
        );
        assert_eq!(names(&dir), before);

        // The production path through a prepared rotation.
        let p = prepare(u);
        let inventory = dir.prepare_inventory(&p, &|| false).unwrap();
        assert_eq!(inventory.generation(), p.new_generation());
        let mut expected = vec![first, second];
        expected.sort();
        let ids: Vec<String> = inventory
            .rows()
            .iter()
            .map(InventoryRow::archive_id_hex)
            .collect();
        assert_eq!(ids, expected);
        SnapshotInventory::decode(&inventory.encode().unwrap())
            .unwrap()
            .verify(inventory.vault_id(), p.new_generation(), p.new_vault_key())
            .unwrap();
    }

    fn hex(id: &[u8; 16]) -> String {
        id.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn snapshot_inventory_dir_publish_read_and_remove_only_matching_files() {
        let (d, a, s) = (TestDir::new(), TestDir::new(), TestDir::new());
        let (path, anchors) = copy_fixture(&d, &a, "v.qvault");
        let dir = snapshot_dir(&s);
        let mut u = unlock(&path, &anchors, PASSWORD).unwrap();
        let first = snapshot(&dir, &mut u, SnapshotKind::Ordinary, 1_700_000_000_000);
        let second = snapshot(&dir, &mut u, SnapshotKind::Ordinary, 1_700_000_200_000);
        let vault_id = u.header().vault_id;
        let p = prepare(u);
        let inventory = dir.prepare_inventory(&p, &|| false).unwrap();
        // Another generation's inventory name stays untouched by publication.
        let older = dir.path().join(file_name(vault_id, KeyGeneration(9)));
        write_file(&older, b"older generation inventory", 0o600);
        let digest = dir.publish_inventory(&inventory).unwrap();
        let published = dir.path().join(file_name(vault_id, p.new_generation()));
        assert_eq!(sha(&published), digest);
        assert_eq!(
            std::fs::read(&older).unwrap(),
            b"older generation inventory"
        );
        assert_eq!(
            dir.publish_inventory(&inventory).err(),
            Some(StoreError::Exists)
        );
        assert!(!names(&dir).iter().any(|n| n.contains(".tmp-")));
        let read = dir.inventory(p.replacement()).unwrap().unwrap();
        assert_eq!(read.rows(), inventory.rows());

        // Only an exactly matching file of a verified row is removed.
        let row = |id: &str| {
            read.rows()
                .iter()
                .find(|r| r.archive_id_hex() == id)
                .unwrap()
                .clone()
        };
        let second_file = dir.path().join(format!("{second}.qvsnap"));
        let mut bytes = std::fs::read(&second_file).unwrap();
        bytes.push(0);
        std::fs::write(&second_file, &bytes).unwrap();
        assert_eq!(
            dir.remove_inventoried(p.replacement(), &row(&second), &|| false),
            Err(StoreError::Integrity)
        );
        assert!(second_file.exists());
        let mut forged = row(&first);
        forged.size += 1;
        assert_eq!(
            dir.remove_inventoried(p.replacement(), &forged, &|| false),
            Err(StoreError::NotFound)
        );
        dir.remove_inventoried(p.replacement(), &row(&first), &|| false)
            .unwrap();
        assert!(!dir.path().join(format!("{first}.qvsnap")).exists());
        assert_eq!(
            dir.remove_inventoried(p.replacement(), &row(&first), &|| false),
            Err(StoreError::NotFound)
        );
        // The source generation has no inventory; without one nothing is
        // removable.
        assert!(dir.inventory(p.source()).unwrap().is_none());
        dir.remove_inventory(vault_id, p.new_generation()).unwrap();
        dir.remove_inventory(vault_id, p.new_generation()).unwrap();
        assert!(dir.inventory(p.replacement()).unwrap().is_none());
        assert_eq!(
            dir.remove_inventoried(p.replacement(), &row(&second), &|| false),
            Err(StoreError::NotFound)
        );
        assert!(second_file.exists());
    }

    #[test]
    fn snapshot_inventory_dir_refuses_hostile_inventory_files() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let (d, a, s) = (TestDir::new(), TestDir::new(), TestDir::new());
        let (path, anchors) = copy_fixture(&d, &a, "v.qvault");
        let dir = snapshot_dir(&s);
        let u = unlock(&path, &anchors, PASSWORD).unwrap();
        let name = dir
            .path()
            .join(file_name(u.header().vault_id, u.header().key_generation));
        let cases: [(&dyn Fn(), StoreError); 4] = [
            (
                &|| write_file(&name, b"not an inventory", 0o600),
                StoreError::Integrity,
            ),
            (
                &|| write_file(&name, &vec![0; MAX_INVENTORY_BYTES + 1], 0o600),
                StoreError::LimitExceeded,
            ),
            (
                &|| {
                    write_file(&name, b"x", 0o600);
                    std::fs::set_permissions(&name, std::fs::Permissions::from_mode(0o644))
                        .unwrap();
                },
                StoreError::UnsafeFile,
            ),
            (
                &|| {
                    let target = dir.path().join("elsewhere");
                    write_file(&target, &vector().encode().unwrap(), 0o600);
                    symlink(&target, &name).unwrap();
                },
                StoreError::UnsafeFile,
            ),
        ];
        for (setup, expected) in cases {
            setup();
            assert_eq!(dir.inventory(&u).err(), Some(expected));
            std::fs::remove_file(&name).unwrap();
        }
        // A valid inventory of another vault under this name is Integrity.
        write_file(&name, &vector().encode().unwrap(), 0o600);
        assert_eq!(dir.inventory(&u).err(), Some(StoreError::Integrity));
    }
}
