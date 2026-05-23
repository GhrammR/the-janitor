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

## CI Monitoring Cadence (after every `git push`)

| Time | Action |
|---|---|
| 1 min | Check `gh pr checks <N>` — Structural Firewall must show pass/fail (not pending) |
| 5 min | All GitHub Actions checks should be pass/fail |
| 9+ min | Governor Janitor Integrity Check resolves; if fail, read log |

A timeout on the Governor check means the `janitor bounce` binary took
>9 min on the PR diff — investigate binary size / diff size.
