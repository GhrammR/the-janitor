# Sprint Outcomes Ledger

Tracks NRA prediction accuracy across sprints. Provides empirical feedback on
which proof-cure → CANDIDATE promotion levers actually convert.

| Sprint | NRA Prediction | Actual Outcome | Delta | Notes |
|--------|---------------|----------------|-------|-------|
| 151 | querybook oauth_missing_state_validation 65% → bounty submission via 30-min manual PoC | Deferred — PoC not yet executed | -65% | No submission yet |
| 152 | keycloak Argon2 40% CANDIDATE → promoted via Go timing cure | Pending P17-3A Go cure shipment | 0 | Blocked on Phase 2 cure |
| 153 | Vault protobuf_any 50% CANDIDATE → phase 4 Docker PoC | PoC confirmed storage-layer only; held at 50% | 0 | Attack path not HTTP-reachable |
| 154 | mattermost/grafana/supabase sweep → new CANDIDATE promotions | 0 promotions; 14 FPs documented | -∞ | Classifier FP batch: proto.Unmarshal != anypb; JWT+WithValidMethods pattern; oauth needs HTTP handler gate |
| 155 | react_xss proof cure unlocks querybook 65% CANDIDATE + mattermost/grafana XSS batch | Phase cures shipped (react_xss + Go timing FP fix). oauth2-proxy 2 CANDIDATEs (30%/20%). casdoor 2 CANDIDATEs (footerHtml XSS 40%, JWT bypass 40%). zitadel 1 CANDIDATE (account fusion 10%). Go timing FP eradicated (passwap.go batch). querybook PoC still deferred. | -30% on querybook | Go timing narrow was mandatory; Sprint 155 hunt sweep produced 3 new CANDIDATEs |
