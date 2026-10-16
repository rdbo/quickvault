# Plans

Implementation plans written by the `quickvault-architect` skill, executed by
`quickvault-developer` and reviewed by `quickvault-reviewer`. Plans are kept
after completion as the record of *how* and *why* something was built; specs
remain the record of *what* the system must do.

## Layout

```
plans/
  NNNN-short-slug/
    PLAN.md     # the plan, plus the developer's execution log
    REVIEW.md   # written by the reviewer
```

Numbers are four digits, increase by one, and are never reused. Find the next one
with `ls plans/`.

## Status lifecycle

Set in the table at the top of `PLAN.md`.

| Status | Meaning | Set by |
|--------|---------|--------|
| `Proposed` | Written, awaiting owner approval | architect |
| `Approved` | Owner agreed; ready to implement | owner (or developer, recording the owner's go-ahead) |
| `In progress` | Being implemented | developer |
| `Blocked` | Stopped on a question for the owner; see execution log | developer |
| `Implemented` | All steps done and verified | developer |
| `Reviewed` | Reviewer approved (possibly with minor fixes) | reviewer |
| `Abandoned` | Not pursued; keep the file and say why | anyone, with owner agreement |

A review that requests changes leaves the status at `Implemented` with a note,
and the developer continues. A re-plan creates a revision section in the same
plan, or a new plan that names the one it supersedes.

## Index

| # | Title | Status |
|---|-------|--------|
| — | No plans yet | — |
