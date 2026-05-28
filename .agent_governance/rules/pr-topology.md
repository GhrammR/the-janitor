# PR Topology Law

## Blast Radius Gate (hard limit)

Every PR targeting `main` must touch **≤5 distinct top-level entries**.
Top-level entries = distinct first path segments of all changed files.

Verification (run before any `gh pr create`):

```bash
git diff --name-only origin/main...HEAD | sed 's|/.*||' | sort -u
```

If the count exceeds 5, split into topic PRs before pushing:

| Topic | Allowed top-level entries |
|---|---|
| Code | `crates/` + `Cargo.lock` + `.INNOVATION_LOG.md` |
| Infrastructure | `.agent_governance/` + `.github/` + `tools/` |
| Docs | `README.md` + `docs/` |

**Never** create a sprint-batch PR spanning all three topics.
`.janitor/` generated artifacts are **never** part of a PR.

## OnceLock Accessor Law — No Structural Clones

When a module needs multiple `OnceLock<AhoCorasick>` statics, **never** write N
separate accessor functions with identical structure. The slop guardian
alpha-normalizes identifiers and will detect N structurally-identical functions as
`logic_clones_found = N×(N-1)/2`, scoring `5 × N×(N-1)/2` pts plus a
`recursive_boilerplate` Critical antipattern at 50 pts — enough to block at ≥3 functions.

**Required pattern** (single parameterized helper, structurally unique):
```rust
fn ac(lock: &'static OnceLock<AhoCorasick>, patterns: &'static [&'static str]) -> &'static AhoCorasick {
    lock.get_or_init(|| {
        AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostFirst)
            .build(patterns)
            .expect("AC build infallible")
    })
}
// Usage: ac(&MY_LOCK, MY_PATTERNS)
```

**Forbidden pattern** (triggers boilerplate flood at ≥3 instances):
```rust
fn foo_ac() -> &'static AhoCorasick {
    FOO_AC.get_or_init(|| { AhoCorasick::builder()... .build(FOO_PATTERNS).expect("...") })
}
fn bar_ac() -> &'static AhoCorasick {  // identical shape → clone
    BAR_AC.get_or_init(|| { AhoCorasick::builder()... .build(BAR_PATTERNS).expect("...") })
}
```

**Root cause (Sprint 178, 2026-05-28):** `kernel.rs` had 9 structurally-identical
OnceLock accessors → `logic_clones_found: 26` (26 × 5 = 130 pts) + one
`recursive_boilerplate` antipattern (50 pts) = slop_score 180 → Structural Firewall block.

## Logic Clone Law

New proof classifiers for `hunt.rs` are **always** added to the
`classify_one_proof` dispatch function — never as new `else if` blocks
inside a `retain_mut` closure.

Pattern to enforce:

```rust
// CORRECT — add to classify_one_proof
} else if id.contains("new_detector_id") {
    po::classify_new_detector_proof(&src(), finding)

// FORBIDDEN — do not replicate this pattern in retain_mut
} else if finding.id.contains("new_detector_id") {
    let source = finding.file.as_deref()
        .and_then(|p| std::fs::read_to_string(dir.join(p)).ok())
        .unwrap_or_default();
    let proof = forge::proof_obligation::classify_new_detector_proof(&source, finding);
    if proof == ProofClass::InvariantViolationProof { return false; }
    finding.proof_class = Some(proof);
}
```

The six-line `retain_mut` clone pattern triggers `logic_clones_found` in
the Structural Firewall and will score 5 pts per clone (gate = 10).

## Branch Source Mandate (before every `git checkout -b`)

**Always branch new feature/sprint work from `origin/main`, never from a `release/vX.Y.Z` branch.**

Release branches contain version-bump artifacts that are NOT in the PR that created them
(SBOM `janitor.cdx.json` files per crate, `Cargo.toml`/`Cargo.lock` version pin,
`docs/index.md`, `README.md`). If you branch from a release branch and that release
PR squash-merges, your new branch base diverges from `main`'s squash commit — every
subsequent PR will drag in all those release artifacts, immediately blowing the
blast-radius gate.

**Correct pattern:**
```bash
git fetch origin
git checkout -b sprint<N>/feature origin/main
```

**Recovery** when you discover you branched from a release branch:
```bash
git fetch origin
git rebase origin/main   # skips already-merged release commit automatically
git push --force-with-lease origin <branch>
```

Then verify the diff is clean:
```bash
git diff --name-only origin/main...HEAD | sed 's|/.*||' | sort -u
```

**Root cause (Sprint 178, 2026-05-28):** `sprint178/p8-4-kernel-primitives` was cut from
`release/v10.2.9` while still checked out. After PR #181 squash-merged the release branch,
the PR #182 diff included all release artifacts (14 `janitor.cdx.json` files, `Cargo.toml`,
`docs/index.md`, `README.md`) — blowing blast-radius and triggering the docs-isolation gate.

## Rebase Mandate (before every `gh pr create`)

**Always rebase the feature branch onto `origin/main` before opening a PR.**

```bash
git fetch origin main
git rebase origin/main
```

If git auto-skips commits (squash-merged ancestors), verify the diff is clean:

```bash
git diff origin/main...HEAD --stat
```

A branch with unresolved divergence from `main` will produce merge conflicts
that suppress `pull_request` event delivery to GitHub Actions, causing
the Governor `Janitor Integrity Check` to time out with no gate run recorded.

## CI Monitoring Cadence (after every `git push` + PR creation)

| Time | Action |
|---|---|
| 60 s | `gh pr checks <N>` — **`Janitor PR Gate` must appear** (queued/running/pass/fail). If absent → re-dispatch immediately (see below). |
| 5 min | All GitHub Actions checks should be pass/fail |
| 9+ min | Governor `Janitor Integrity Check` resolves |

### Governor `Janitor Integrity Check` timeout — diagnosis

A `timed_out` conclusion on the Governor check means **the `Janitor PR Gate`
GitHub Actions workflow did not deliver its bounce result to the Governor within
9 minutes**. Two root causes:

| Cause | Symptom | Fix |
|---|---|---|
| Workflow never triggered | `gh run list` shows NO Janitor PR Gate run for the PR head SHA | Re-dispatch (see below) |
| Bounce exceeded 120 s timeout | Janitor PR Gate run exists but timed out | Investigate diff size / binary budget |

### Re-dispatch command (workflow not triggered)

```bash
gh workflow run janitor-pr-gate.yml \
  --repo janitor-security/the-janitor \
  --ref <head-branch> \
  -f pr_number=<N>
```

After dispatching, re-check within 90 s: `gh pr checks <N> --watch`.

## Law PT-IV — Never Accumulate Multiple Fixes on a Branch Already Partially Merged via Squash

When a PR is squash-merged, GitHub creates a new commit on `main` whose tree
matches the PR tip but whose parents differ from the branch's commits. Any
subsequent commits pushed to that same branch will **conflict** on the next
PR against `main` because git cannot detect the squash relationship.

**Required pattern:** one branch = one PR = one squash commit. After a PR merges:
1. Immediately branch from fresh `origin/main` for follow-on work.
2. Never push additional commits to a branch whose PR has already been squash-merged.

**Recovery** when a conflict is detected (`mergeStateStatus: DIRTY`):
```bash
git fetch origin main
git rebase origin/main   # git skips already-merged commits automatically
git push --force-with-lease origin <branch>
```

The rebase will skip the squash-merged commit with `warning: skipped previously
applied commit` — this is expected and correct. Only the new, unmerged commits
remain.

**Root cause (Sprint 173, 2026-05-26):** PR #163 squash-merged the first commit
of `sprint173/fix-dependabot-automerge`. Two subsequent governance/workflow
commits were pushed to the same branch, creating PR #164. GitHub reported
`mergeable: CONFLICTING` / `mergeStateStatus: DIRTY`. Fixed by `git rebase
origin/main` which auto-skipped the already-merged commit.
