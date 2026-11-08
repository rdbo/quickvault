# QuickVault proposed LAN authentication diagram

**Latest candidate: [DESIGN-v4.md](DESIGN-v4.md)** with
[editable Mermaid](lan-auth-v4.mmd), [SVG](lan-auth-v4.svg) and
[PNG](lan-auth-v4.png). It reviews v3 after its §13 and removes all stored
password-authentication state: A's user types the vault password when
approving, and A builds a per-session credential. No storage-format change,
four password-path flights, two key-path flights. Exploratory and unreviewed;
everything below is history.

The owner selected v4 on 2026-11-08. Its concrete implementation work, together
with the other two discussed assessment topics, is proposed in
[plan 0047](../../0047-audit-policy-and-lan-auth/PLAN.md). Selection of the
direction does not make this diagram a normative spec or a reviewed protocol.

The previous product-specific candidate is [DESIGN-v3.md](DESIGN-v3.md), with
[editable Mermaid](lan-auth-v3.mmd), [SVG](lan-auth-v3.svg) and
[PNG](lan-auth-v3.png). It is exploratory and not independently validated, not an accepted
replacement for the implemented protocol. Its review,
[REVIEW-v3.md](REVIEW-v3.md), keeps the direction and proposes a simpler
message flow (four password-path messages instead of nine). V1/v2 and the v2 review remain here
as history. The [v3 follow-up review](REVIEW-v3-followup.md) requests migration,
KDF and grant-concurrency refinements and qualifies the proposed simplifications.
The owner's request for solutions is addressed in
[the design's resolution section](DESIGN-v3.md#13-proposed-resolutions-to-the-follow-up-review).
It proposes incompatible format gates, explicit Argon2id settings, atomic
grant sealing and retention of both Finished messages; these refinements have
not received a follow-up approval.
No conformance claim substitutes for analyzing this construction.

This is an exploratory diagram of the conversation's proposal, not an accepted
protocol, an implementation plan, or evidence that the composition is secure.
OPAQUE is shown as the password-route candidate. The PAKE suite, credential
provisioning/migration, channel binding, precise encodings, KDF domain labels,
and security assumptions still require specification and independent review.

Files:
- `lan-auth.mmd`: editable Mermaid sequence-diagram source.
- `lan-auth.svg`: scalable vector export; editable in an SVG editor.
- `lan-auth.png`: full-resolution raster export.
- `mermaid.json`: layout and colour configuration.
- `lan-auth-v3.mmd` / `.svg` / `.png`: the product-specific candidate, including
  explicit listener closure, separate secret-state serialization, credential-
  bound traffic keys, private bootstrap context and pre-transfer grant checks.
- `DESIGN-v3.md`: construction, secret lifetimes, lifecycle, rejected shortcuts
  and an attack worksheet for v3.
- `lan-auth-v2.mmd` / `.svg` / `.png`: revised flow after analysis
  (two modes, OPAQUE state in the VK-encrypted keyslot record, PAKE key folded
  into the record keys, no VK proof on the password route).
- `ANALYSIS.md`: findings on `lan-auth`, rationale for v2, adversary
  comparison and the spec text v2 would need. Read it when examining v2.

Re-export after editing, using Mermaid CLI:

```sh
mmdc -i lan-auth.mmd -o lan-auth.svg -c mermaid.json --size 5000 -b white
mmdc -i lan-auth.mmd -o lan-auth.png -c mermaid.json --size 5000 -b white
```

Use the same commands with `lan-auth-v2` or `lan-auth-v3` for those diagrams.
Run those commands from this directory. If required by your environment, pass
a local Puppeteer configuration with `-p`; browser paths and writable cache
locations are environment-specific and are not checked into this directory.
The Mermaid source can also be edited in another Mermaid-compatible editor.

Cryptographic notation for the original `lan-auth` diagram (v1):
- P: the one-use pairing secret displayed in the QR.
- VK: the 256-bit vault key. Recovery words encode VK directly in QuickVault.
- ss: the shared secret from the ephemeral X-Wing hybrid KEM.
- TH: a digest binding the outer handshake messages.
- CTX: the proposed authentication context; precise fields/encoding are pending.
- K_PAKE: secret output of successfully completed PAKE authentication.
- K_grant: a purpose-separated key derived from K_PAKE for wrapping VK.
- K_confirm: a separate key derived from VK for session-bound possession proofs.
- AEAD: authenticated encryption. The existing product profile is
  XChaCha20-Poly1305 with a random 24-byte nonce; the proposed grant envelope
  needs its own reviewed use of that profile.
- HKDF/HMAC: the existing product profiles use SHA-512; MAC/1 truncates HMAC
  to 32 bytes. Formula labels in this diagram are symbolic, not assigned wire
  strings or complete byte-level specifications.

Only the initial bootstrap occurs outside the outer encrypted record layer.
The comparison-code check and source-side approval remain in the proposal.
The password route requires successful PAKE confirmation before any VK grant;
the recovery route performs no VK grant. In v1 both routes explicitly confirm
possession of VK before the emitter transfers vault objects. In v2 the password
route instead uses PAKE-confirmed record keys and the post-transfer consistency
check; only its VK route uses the explicit VK-possession proofs.

The follow-up [review](REVIEW.md) requests corrections to the v2 analysis and
diagram. The proposal has not been approved for implementation.

An unlocked emitter holding only VK cannot manufacture PAKE registration state
for the user's password. Trusted credential setup is a prerequisite. It cannot
be delegated to an unauthenticated joining device. Password changes, recovery,
and existing vault migration need explicit designs.

References:
- OPAQUE: https://www.rfc-editor.org/rfc/rfc9807.html
- Authenticated encryption: https://www.rfc-editor.org/rfc/rfc5116.html
- Existing local profile/recovery definitions: specs/0002-cryptography.md

These are exploratory documentation artifacts. No production code or accepted
protocol requirements are changed by this diagram.
