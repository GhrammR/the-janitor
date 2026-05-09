# Sprint Batch 136 — Hunt Summary

| Target | Result |
|--------|--------|
| smartcontractkit/chainlink-docs | p2_14_demoted_to_informational — all `security:dom_xss_innerHTML` findings on `source/javascripts/lib/_jquery.js` (lines 1184, 4334, 5508, etc.) are now demoted to `Informational` by `apply_p2_14_vendored_dom_demotion`. The vendor file matches `is_vendored_library_path` (filename contains `jquery`) and the source carries no repository-native attacker-reachable DOM reflection witness. The previously-recorded chainlink-docs jQuery `LOW_YIELD_LEDGER` row's R&D Follow-Up is now structurally fulfilled. |
| cashapp/hermit | low_yield_heredoc_url_fp — 2× `security:unpinned_asset` findings on `cmd/geninstaller/install.sh.tmpl:117` and `files/install.sh.tmpl:117`. Both lines are inside a `cat <<-EOF ... EOF` heredoc that prints documentation pointers; the URL is help text, not a `curl`/`wget` target. Threat Model Awareness routes these as Approval% < 10. Pre-existing LOW_YIELD entry covers the class. |
