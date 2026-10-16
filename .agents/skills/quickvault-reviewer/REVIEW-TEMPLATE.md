# Review — Plan NNNN: Title

| Verdict | Reviewed | Diff reviewed |
|---------|----------|---------------|
| Approved / Approved with minor fixes / Changes requested / Re-plan needed | YYYY-MM-DD | `git diff master...HEAD` (abc1234) |

## Summary

<2–4 sentences: what was built, whether it matches the plan, overall quality.>

## Plan conformance

| Step | Done | Notes |
|------|------|-------|
| 1 | yes / partial / no | |

Out-of-scope changes: <None | list>

## Findings

<Most severe first. Severity: critical / high / medium / low.>

1. **[severity] Title** — `path/to/file.rs:42`
   What's wrong, why it matters (spec section if any), suggested direction.
   Action: escalated / fixed by reviewer.

## Fixes applied by reviewer

- `path:line` — what changed and why it counts as minor.

## Gates

| Check | Result |
|-------|--------|
| `cargo fmt --check` | pass / fail / n/a (no workspace) |
| `cargo clippy --all-targets --locked -- -D warnings` | |
| `cargo test --locked` | |
| `cargo deny check` (if deps changed) | |

## Documentation

- [ ] CHANGELOG.md
- [ ] ARCHITECTURE.md (if structure changed)
- [ ] Spec statuses and Changelogs
- [ ] Plan ticks, execution log, plans/README.md row

## Escalations for the owner

<What needs a decision or a re-plan. For a re-plan, include the problem
statement for quickvault-architect.>
