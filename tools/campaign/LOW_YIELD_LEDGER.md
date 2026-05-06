# Low-Yield Ledger

Findings with an estimated Approval % below 10 are archived here instead of deleted. They are not submission candidates; they are retained as negative training data for Omni-Audits, future AEG templates, and AST false-positive suppressions.

| Date | Target | Finding | Approval % | Reason Routed | R&D Follow-up |
|------|--------|---------|------------|---------------|---------------|
| 2026-05-06 | https://github.com/fireblocks/mpc-lib | security:lcm_double_free | 5 | Static LCM pattern emitted only manual pentester notes; no route, attacker-controlled input, or concrete repro_cmd was proven. | Add bounded C ownership-lifetime witness synthesis for paired free paths before bounty escalation. |
| 2026-05-06 | https://github.com/fireblocks/mpc-lib | security:lcm_use_after_free | 5 | Static LCM pattern emitted only manual pentester notes; no route, attacker-controlled input, or concrete repro_cmd was proven. | Add interprocedural C lifetime graph proof that demonstrates reachable post-free dereference from public parser/API input. |
| 2026-05-06 | https://github.com/fireblocks/mpc-lib | security:lcm_malloc_integer_truncation | 5 | Static LCM pattern emitted only manual pentester notes; allocation size controllability was not proven. | Add Z3-backed allocation-width model that extracts attacker-controlled length bounds from C arithmetic before reporting. |
| 2026-05-06 | https://github.com/fireblocks/mpc-lib | security:lcm_off_by_one_loop | 5 | Static LCM pattern emitted only manual pentester notes; no input-dependent loop bound or crash proof was generated. | Add C loop-bound witness generation with sanitizer-aware range proof and deterministic crash harness synthesis. |
