// SPDX-License-Identifier: AGPL-3.0-or-later

//! Group, entry, field and attachment payload tests (plan 0007 step 4).

use proptest::prelude::*;

use super::*;
use crate::clock::test_clock::clock;
use crate::ids::test_ids::{fid, oid, rid, v4, vid};
use crate::ids::{ObjectId, RandomId};
use crate::record::test_records::*;
use crate::record::{Deletion, RecordBody, RecordVersion};
use crate::text::{Extensions, FieldValue, MAX_TEXT_BYTES, Text};
use crate::time::Timestamp;

fn decode(entries: &[(i64, Vec<u8>)]) -> Result<RecordVersion, ModelError> {
    RecordVersion::decode(&map(entries))
}

fn round_trip(bytes: &[u8]) -> RecordVersion {
    let v = RecordVersion::decode(bytes).unwrap();
    assert_eq!(v.encode().unwrap().as_slice(), bytes);
    v
}

fn field_map(id: [u8; 16], name: &str, kind: u64, value: Vec<u8>, protected: bool) -> Vec<u8> {
    map(&[
        (0, bytes(&id)),
        (1, text(name)),
        (2, uint(kind)),
        (3, value),
        (4, boolean(protected)),
    ])
}

fn array(items: &[Vec<u8>]) -> Vec<u8> {
    let mut e = qv_encoding::Encoder::new();
    e.array(|a| {
        for i in items {
            a.raw(&qv_encoding::RawValue::from_canonical(i).unwrap())?;
        }
        Ok(())
    })
    .unwrap();
    e.finish().unwrap().to_vec()
}

fn entry_payload(fields: Vec<Vec<u8>>) -> Vec<(i64, Vec<u8>)> {
    vec![
        (0, bytes(&v4(0x10))),
        (1, text("login")),
        (2, text("Example")),
        (3, array(&fields)),
        (7, int(1)),
        (8, int(2)),
    ]
}

fn group_payload(parent: Option<[u8; 16]>) -> Vec<(i64, Vec<u8>)> {
    vec![
        (0, parent.map_or_else(null, |p| bytes(&p))),
        (1, text("G")),
        (4, text("a0")),
    ]
}

fn attachment_payload(size: u64, chunks: &[[u8; 16]]) -> Vec<(i64, Vec<u8>)> {
    vec![
        (0, bytes(&v4(0x10))),
        (1, text("a.txt")),
        (2, text("text/plain")),
        (3, uint(size)),
        (4, uint(chunks.len() as u64)),
        (
            5,
            array(&chunks.iter().map(|c| bytes(c)).collect::<Vec<_>>()),
        ),
        (6, bytes(&[0x5a; 32])),
    ]
}

/// A v4 ID unique for `n` up to 2^16.
fn wide(n: u32) -> [u8; 16] {
    let mut b = v4(0xee);
    b[1] = (n >> 8) as u8;
    b[2] = n as u8;
    b
}

fn entry_version(payload: Entry) -> RecordVersion {
    RecordVersion {
        version_id: vid(0xa1),
        clock: clock(&[(0xb1, 1)]),
        modified_at: Timestamp(1_700_000_000_000),
        body: RecordBody::Live(Payload::Entry(payload)),
        ext: Extensions::new(),
    }
}

#[test]
fn payload_entry_api_matches_wire_bytes() {
    let fields = vec![
        Field {
            id: fid(1),
            name: Text::new("Username").unwrap(),
            kind: FieldKind::Text,
            value: FieldValue::text("alice").unwrap(),
            protected: false,
            ext: Extensions::new(),
        },
        Field {
            id: fid(2),
            name: Text::new("Password").unwrap(),
            kind: FieldKind::Secret,
            value: FieldValue::bytes(b"\x00hunter2").unwrap(),
            protected: true,
            ext: Extensions::new(),
        },
        Field {
            id: fid(3),
            name: Text::new("OTP").unwrap(),
            kind: FieldKind::Totp,
            value: FieldValue::text("otpauth://totp/x?secret=GEZDGNBV").unwrap(),
            protected: true,
            ext: Extensions::new(),
        },
    ];
    let entry = Entry {
        group: rid(0x10),
        type_hint: Text::new("login").unwrap(),
        title: Text::new("Example").unwrap(),
        fields,
        notes: None,
        icon: None,
        expires_at: None,
        created_at: Timestamp(1),
        modified_at: Timestamp(2),
        deleted_at: None,
        ext: Extensions::new(),
    };
    let encoded = entry_version(entry).encode().unwrap();
    let wire = map(&envelope(
        2,
        false,
        Some(map(&entry_payload(vec![
            field_map(v4(1), "Username", 0, text("alice"), false),
            field_map(v4(2), "Password", 1, bytes(b"\x00hunter2"), true),
            field_map(
                v4(3),
                "OTP",
                4,
                text("otpauth://totp/x?secret=GEZDGNBV"),
                true,
            ),
        ]))),
    ));
    assert_eq!(encoded.as_slice(), wire.as_slice());
    let v = round_trip(&wire);
    let RecordBody::Live(Payload::Entry(e)) = &v.body else {
        panic!("not an entry");
    };
    assert_eq!(e.fields.len(), 3);
    assert_eq!(e.fields[1].value.expose_secret(), b"\x00hunter2");
    assert!(matches!(e.fields[1].value, FieldValue::Bytes(_)));
    assert!(matches!(e.fields[0].value, FieldValue::Text(_)));
    assert_eq!(e.fields[2].kind, FieldKind::Totp);
    assert_eq!(format!("{:?}", e.fields[0]), "Field(<redacted>)");
    assert_eq!(format!("{e:?}"), "Entry(<redacted>)");
}

#[test]
fn payload_group_golden() {
    let bytes = map(&group_payload(None));
    // {0: null, 1: "G", 4: "a0"}
    assert_eq!(
        bytes,
        [0xa3, 0x00, 0xf6, 0x01, 0x61, b'G', 0x04, 0x62, b'a', b'0']
    );
    let v = round_trip(&map(&envelope(1, false, Some(bytes))));
    let RecordBody::Live(Payload::Group(g)) = &v.body else {
        panic!("not a group");
    };
    assert!(g.parent.is_none());
    let child = round_trip(&map(&envelope(
        1,
        false,
        Some(map(&group_payload(Some(v4(9))))),
    )));
    let RecordBody::Live(Payload::Group(g)) = &child.body else {
        panic!("not a group");
    };
    assert_eq!(g.parent, Some(rid(9)));
    // Every optional key present.
    let full = [
        group_payload(Some(v4(9))),
        vec![(2, text("n")), (3, text("folder")), (5, int(-5))],
    ]
    .concat();
    round_trip(&map(&envelope(1, false, Some(map(&full)))));
    for k in [0, 1, 4] {
        assert_eq!(
            decode(&envelope(
                1,
                false,
                Some(map(&without(&group_payload(None), k)))
            ))
            .map(|_| ()),
            Err(ModelError::Malformed),
            "group key {k}"
        );
    }
}

#[test]
fn payload_unknown_keys_in_entry_and_field() {
    let f = map(&[
        (0, bytes(&v4(1))),
        (1, text("N")),
        (2, uint(0)),
        (3, text("v")),
        (4, boolean(false)),
        (5, text("future")),
        (-2, uint(3)),
    ]);
    let mut p = entry_payload(vec![f]);
    p.push((10, array(&[uint(1)])));
    let v = round_trip(&map(&envelope(2, false, Some(map(&p)))));
    let RecordBody::Live(Payload::Entry(e)) = &v.body else {
        panic!("not an entry");
    };
    assert_eq!(e.ext.len(), 1);
    assert_eq!(e.fields[0].ext.len(), 2);
}

#[test]
fn payload_entry_missing_keys() {
    let p = entry_payload(vec![]);
    for k in [0, 1, 2, 3, 7, 8] {
        assert_eq!(
            decode(&envelope(2, false, Some(map(&without(&p, k))))).map(|_| ()),
            Err(ModelError::Malformed),
            "entry key {k}"
        );
    }
    let f = [
        (0, bytes(&v4(1))),
        (1, text("N")),
        (2, uint(0)),
        (3, text("v")),
        (4, boolean(false)),
    ];
    for k in 0..=4 {
        let p = entry_payload(vec![map(&without(&f, k))]);
        assert_eq!(
            decode(&envelope(2, false, Some(map(&p)))).map(|_| ()),
            Err(ModelError::Malformed),
            "field key {k}"
        );
    }
    // A value that is neither text nor bytes.
    let p = entry_payload(vec![field_map(v4(1), "N", 0, uint(5), false)]);
    assert_eq!(
        decode(&envelope(2, false, Some(map(&p)))).map(|_| ()),
        Err(ModelError::Malformed)
    );
}

#[test]
fn payload_field_count_limit() {
    let make = |n: u32| {
        let fields: Vec<_> = (0..n)
            .map(|i| field_map(wide(i), "", 0, text(""), false))
            .collect();
        map(&envelope(2, false, Some(map(&entry_payload(fields)))))
    };
    let v = round_trip(&make(4096));
    let RecordBody::Live(Payload::Entry(e)) = &v.body else {
        panic!("not an entry");
    };
    assert_eq!(e.fields.len(), MAX_FIELDS);
    assert_eq!(
        RecordVersion::decode(&make(4097)).map(|_| ()),
        Err(ModelError::LimitExceeded)
    );
}

#[test]
fn payload_field_rejections() {
    let dup = entry_payload(vec![
        field_map(v4(1), "a", 0, text("x"), false),
        field_map(v4(1), "b", 0, text("y"), false),
    ]);
    assert_eq!(
        decode(&envelope(2, false, Some(map(&dup)))).map(|_| ()),
        Err(ModelError::Malformed)
    );
    let big = "a".repeat(MAX_TEXT_BYTES + 1);
    for value in [text(&big), bytes(big.as_bytes())] {
        let p = entry_payload(vec![field_map(v4(1), "a", 0, value, false)]);
        assert_eq!(
            decode(&envelope(2, false, Some(map(&p)))).map(|_| ()),
            Err(ModelError::LimitExceeded)
        );
    }
    // A title over the limit.
    let p = with(&entry_payload(vec![]), 2, text(&big));
    assert_eq!(
        decode(&envelope(2, false, Some(map(&p)))).map(|_| ()),
        Err(ModelError::LimitExceeded)
    );
    // At the limit, a value is accepted.
    let max = "a".repeat(MAX_TEXT_BYTES);
    let p = entry_payload(vec![field_map(v4(1), "a", 0, bytes(max.as_bytes()), false)]);
    round_trip(&map(&envelope(2, false, Some(map(&p)))));
}

#[test]
fn payload_unknown_field_kind() {
    let p = entry_payload(vec![field_map(v4(1), "a", 9, text("x"), true)]);
    let mut v = round_trip(&map(&envelope(2, false, Some(map(&p)))));
    let RecordBody::Live(Payload::Entry(e)) = &mut v.body else {
        panic!("not an entry");
    };
    assert_eq!(e.fields[0].kind, FieldKind::Unknown(9));
    // An "unknown" kind with a known code would not round-trip.
    e.fields[0].kind = FieldKind::Unknown(3);
    assert_eq!(v.encode().map(|_| ()), Err(ModelError::Malformed));
}

#[test]
fn payload_protected_defaults() {
    use FieldKind::*;
    for k in [Secret, Totp] {
        assert!(k.protected_by_default());
    }
    for k in [Text, Url, Email, Multiline, Date, Unknown(7)] {
        assert!(!k.protected_by_default());
    }
}

#[test]
fn payload_attachment_sizes() {
    let ok = |size: u64, n: u32| {
        let chunks: Vec<_> = (0..n).map(wide).collect();
        let v = round_trip(&map(&envelope(
            3,
            false,
            Some(map(&attachment_payload(size, &chunks))),
        )));
        let RecordBody::Live(Payload::AttachmentMeta(a)) = &v.body else {
            panic!("not attachment meta");
        };
        assert_eq!(a.chunk_object_ids.len(), n as usize);
        assert_eq!(a.content_hash, [0x5a; 32]);
    };
    ok(0, 0);
    ok(1, 1);
    ok(CHUNK_SIZE, 1);
    ok(CHUNK_SIZE + 1, 2);
    ok(MAX_ATTACHMENT_BYTES, 160);
    let bad = |p: Vec<(i64, Vec<u8>)>, err: ModelError| {
        assert_eq!(
            decode(&envelope(3, false, Some(map(&p)))).map(|_| ()),
            Err(err)
        );
    };
    // Size and list disagree.
    bad(
        attachment_payload(CHUNK_SIZE + 1, &[wide(0)]),
        ModelError::Malformed,
    );
    bad(attachment_payload(0, &[wide(0)]), ModelError::Malformed);
    // chunk_count disagrees with the list.
    bad(
        with(&attachment_payload(1, &[wide(0)]), 4, uint(2)),
        ModelError::Malformed,
    );
    // Duplicate chunk IDs.
    bad(
        attachment_payload(CHUNK_SIZE + 1, &[wide(0), wide(0)]),
        ModelError::Malformed,
    );
    // Over the client maximum.
    let chunks: Vec<_> = (0..161).map(wide).collect();
    bad(
        attachment_payload(MAX_ATTACHMENT_BYTES + 1, &chunks),
        ModelError::LimitExceeded,
    );
    bad(
        attachment_payload(MAX_ATTACHMENT_BYTES + 1, &chunks[..160]),
        ModelError::LimitExceeded,
    );
    for k in 0..=6 {
        bad(
            without(&attachment_payload(0, &[]), k),
            ModelError::Malformed,
        );
    }
    // A content hash of the wrong length.
    bad(
        with(&attachment_payload(0, &[]), 6, bytes(&[0; 31])),
        ModelError::Malformed,
    );
}

#[test]
fn payload_attachment_encode_checks() {
    let meta = AttachmentMeta {
        entry: rid(1),
        name: Text::new("a").unwrap(),
        mime: Text::new("b").unwrap(),
        size: CHUNK_SIZE + 1,
        chunk_object_ids: vec![oid(1)],
        content_hash: [0; 32],
        ext: Extensions::new(),
    };
    let mut v = RecordVersion {
        version_id: vid(1),
        clock: clock(&[(1, 1)]),
        modified_at: Timestamp(0),
        body: RecordBody::Live(Payload::AttachmentMeta(meta)),
        ext: Extensions::new(),
    };
    assert_eq!(v.encode().map(|_| ()), Err(ModelError::Malformed));
    if let RecordBody::Live(Payload::AttachmentMeta(a)) = &mut v.body {
        a.chunk_object_ids.push(ObjectId::generate().unwrap());
    }
    assert!(v.encode().is_ok());
}

#[test]
fn payload_check_root() {
    let root = decode(&envelope(1, false, Some(map(&group_payload(None))))).unwrap();
    assert_eq!(root.check_root(), Ok(()));
    let with_parent = decode(&envelope(1, false, Some(map(&group_payload(Some(v4(9))))))).unwrap();
    assert_eq!(with_parent.check_root(), Err(ModelError::InvalidTransition));
    let trashed = with(&group_payload(None), 5, int(7));
    let trashed = decode(&envelope(1, false, Some(map(&trashed)))).unwrap();
    assert_eq!(trashed.check_root(), Err(ModelError::InvalidTransition));
    let tomb = decode(&envelope(1, true, None)).unwrap();
    assert_eq!(tomb.check_root(), Err(ModelError::InvalidTransition));
    let entry = decode(&envelope(2, false, Some(map(&entry_payload(vec![]))))).unwrap();
    assert_eq!(entry.check_root(), Err(ModelError::InvalidTransition));
}

#[test]
fn payload_deletion_states() {
    let live_group = decode(&envelope(1, false, Some(map(&group_payload(None))))).unwrap();
    assert_eq!(live_group.deletion(), Deletion::Live);
    let soft_group = decode(&envelope(
        1,
        false,
        Some(map(&with(&group_payload(None), 5, int(1)))),
    ))
    .unwrap();
    assert_eq!(soft_group.deletion(), Deletion::SoftDeleted);
    let live_entry = decode(&envelope(2, false, Some(map(&entry_payload(vec![]))))).unwrap();
    assert_eq!(live_entry.deletion(), Deletion::Live);
    let soft_entry = decode(&envelope(
        2,
        false,
        Some(map(&with(&entry_payload(vec![]), 9, int(1)))),
    ))
    .unwrap();
    assert_eq!(soft_entry.deletion(), Deletion::SoftDeleted);
    for kind in [1, 2, 3] {
        let t = round_trip(&map(&envelope(kind, true, None)));
        assert_eq!(t.deletion(), Deletion::Final);
        assert_eq!(t.kind().code(), kind);
    }
    let att = decode(&envelope(3, false, Some(map(&attachment_payload(0, &[]))))).unwrap();
    assert_eq!(att.deletion(), Deletion::Live);
}

/// Valid encodings of every kind, for mutation.
fn samples() -> Vec<Vec<u8>> {
    vec![
        map(&envelope(1, false, Some(map(&group_payload(Some(v4(9))))))),
        map(&envelope(
            2,
            false,
            Some(map(&entry_payload(vec![
                field_map(v4(1), "u", 0, text("alice"), false),
                field_map(v4(2), "p", 1, bytes(b"pw"), true),
            ]))),
        )),
        map(&envelope(
            3,
            false,
            Some(map(&attachment_payload(1, &[wide(1)]))),
        )),
        map(&envelope(2, true, None)),
        map(&envelope(
            0,
            false,
            Some(map(&[
                (0, text("V")),
                (2, bytes(&v4(2))),
                (3, map(&[(0, uint(3))])),
            ])),
        )),
    ]
}

/// Decoding never panics; anything accepted re-encodes to the same bytes.
fn check_canonical(bytes: &[u8]) -> Result<(), TestCaseError> {
    if let Ok(v) = RecordVersion::decode(bytes) {
        let again = v.encode();
        prop_assert!(again.is_ok());
        if let Ok(again) = again {
            prop_assert_eq!(again.as_slice(), bytes);
        }
    }
    Ok(())
}

proptest! {
    #[test]
    fn payload_decode_arbitrary_bytes(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
        check_canonical(&bytes)?;
    }

    #[test]
    fn payload_decode_mutations(sample in 0usize..5, pos in any::<prop::sample::Index>(), byte in any::<u8>(), cut in any::<bool>()) {
        let mut b = samples().swap_remove(sample);
        let i = pos.index(b.len());
        if cut {
            b.truncate(i);
        } else {
            b[i] = byte;
        }
        check_canonical(&b)?;
    }
}

fn keyslot_map() -> Vec<(i64, Vec<u8>)> {
    vec![
        (0, bytes(&v4(0x03))),
        (1, uint(1)),
        (2, bytes(&[0x11; 32])),
        (3, uint(1)),
        (4, bytes(&[0x22; 32])),
        (5, bytes(&[0x33; 24])),
        (6, bytes(&[0x44; 48])),
    ]
}

#[test]
fn payload_non_v4_crypto_ids_are_not_encoded() {
    // The qv-crypto IDs have public fields; encode must refuse what decode
    // would reject (review 0007 finding 1).
    let bad = qv_crypto::RecordId([0; 16]);
    let vault_meta = map(&[(0, text("V")), (2, bytes(&v4(0x02))), (3, map(&[]))]);
    let cases: Vec<(u64, Vec<u8>)> = vec![
        (0, vault_meta),
        (1, map(&group_payload(Some(v4(0x20))))),
        (2, map(&entry_payload(vec![]))),
        (3, map(&attachment_payload(0, &[]))),
        (4, map(&keyslot_map())),
    ];
    for (kind, payload) in cases {
        let mut v = round_trip(&map(&envelope(kind, false, Some(payload))));
        let RecordBody::Live(p) = &mut v.body else {
            panic!("not live");
        };
        match p {
            Payload::VaultMeta(m) => m.root_group = bad,
            Payload::Group(g) => g.parent = Some(bad),
            Payload::Entry(e) => e.group = bad,
            Payload::AttachmentMeta(a) => a.entry = bad,
            Payload::PasswordKeyslot(k) => k.slot.slot_id = qv_crypto::SlotId([0; 16]),
        }
        assert_eq!(v.encode().err(), Some(ModelError::Malformed), "kind {kind}");
    }
    // A root group (parent null) still encodes.
    round_trip(&map(&envelope(1, false, Some(map(&group_payload(None))))));
}

#[test]
fn payload_keyslot_standalone_codec() {
    let bytes_in = map(&keyslot_map());
    let k = Keyslot::decode(&bytes_in).unwrap();
    assert_eq!(k.encode().unwrap().as_slice(), bytes_in.as_slice());
    // The same bytes as the payload inside a keyslot record version.
    let record = map(&envelope(4, false, Some(bytes_in.clone())));
    let v = round_trip(&record);
    let RecordBody::Live(Payload::PasswordKeyslot(inner)) = &v.body else {
        panic!("not a keyslot");
    };
    assert_eq!(inner.encode().unwrap().as_slice(), bytes_in.as_slice());
    assert!(record.ends_with(&bytes_in));

    // Unknown keys survive.
    let with_ext = map(&with(&keyslot_map(), 9, text("x")));
    let k = Keyslot::decode(&with_ext).unwrap();
    assert_eq!(k.ext.len(), 1);
    assert_eq!(k.encode().unwrap().as_slice(), with_ext.as_slice());

    // Rejections.
    let mut trailing = bytes_in.clone();
    trailing.push(0x00);
    assert_eq!(
        Keyslot::decode(&trailing).err(),
        Some(ModelError::Malformed)
    );
    let unknown_kdf = map(&with(&keyslot_map(), 1, uint(2)));
    assert_eq!(
        Keyslot::decode(&unknown_kdf).err(),
        Some(ModelError::Unsupported)
    );
    for key in 0..7 {
        let missing = map(&without(&keyslot_map(), key));
        assert_eq!(
            Keyslot::decode(&missing).err(),
            Some(ModelError::Malformed),
            "key {key}"
        );
    }
    let too_big = vec![0u8; crate::text::MAX_RECORD_BYTES + 1];
    assert_eq!(
        Keyslot::decode(&too_big).err(),
        Some(ModelError::LimitExceeded)
    );
    let mut k = Keyslot::decode(&bytes_in).unwrap();
    k.slot.slot_id = qv_crypto::SlotId([0; 16]);
    assert_eq!(k.encode().err(), Some(ModelError::Malformed));
}
