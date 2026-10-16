# Plan NNNN — Title

| Status | Created | Approved | Specs |
|--------|---------|----------|-------|
| Proposed | YYYY-MM-DD | — | 0004 §5, 0011 §4 |

## Intent

<What the user wants and why, in their terms. 1–3 sentences.>

## Scope

**In scope:**
-

**Out of scope:**
-

## Spec basis

| Behaviour | Spec | Spec status | Notes |
|-----------|------|-------------|-------|
| | | | |

**Spec changes required:** <None | which spec, what change, which step>

## Decisions needed

<Write "None" if empty. The developer must not start steps that depend on an
open item here.>

1. **<Question>** — Options: A / B. Recommendation: A, because …
   Blocks: Step N. Resolution: <pending | owner chose X on YYYY-MM-DD>

## Design

**Components touched:** <crates/modules, and which trust boundary each sits on>

**Interfaces:**

```rust
// Public types and signatures to create or change, sketched.
```

**Data and control flow:** <including transaction / crash-point ordering for writes>

**Secrets and hostile input:** <which types hold secrets; bounds and authentication before parsing>

**Errors:** <error types; what users see; redaction>

**Dependencies:**

| Crate | Why | Alternatives | Review / audit status |
|-------|-----|--------------|-----------------------|
| | | | |

## Steps

### Step 1 — <title>

- [ ] **Do:**
- **Files:**
- **Done when:**
- **Verify:** `cargo test --locked -p <crate> <filter>`

### Step 2 — <title>

- [ ] **Do:**
- **Files:**
- **Done when:**
- **Verify:**

## Test plan

- Unit and property tests:
- Rejection, malformed-input and crash-path tests:
- Vectors (golden files, known-answer tests):
- 0012 §1 matrix rows addressed:

## Risks and stop conditions

<Specific situations where the developer must stop and ask instead of improvising.>

-

## Documentation

- [ ] `CHANGELOG.md` — Unreleased entry
- [ ] `ARCHITECTURE.md` — <section, or "no change">
- [ ] Specs — <amendments, Changelog lines, status changes, or "no change">
- [ ] `AGENTS.md` — <if conventions or layout changed, or "no change">

## Revisions

<Dated entries when the plan changes after it was proposed.>

## Execution log

<The developer appends dated entries: steps completed, deviations and why,
questions asked and the answers, and issues found but deliberately not fixed.>
