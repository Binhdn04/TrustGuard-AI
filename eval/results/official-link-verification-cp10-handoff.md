# Official Link Verification CP10 Handoff

## Result

WP10 implementation and offline verification are complete. The immutable `security-v4-v2` dataset, deterministic
production-path evaluator, hosted-evidence validator and privacy-minimized hosted hard-case smoke are in place. All
offline CP10 thresholds and repository test gates pass.

CP10 release approval remains pending. No reviewed hosted evidence, hosted OIDC token/provider configuration or
running Docker daemon was available, so PostgreSQL/Redis/worker, OIDC/RBAC, backup/restore, live provider/failure,
load and rollout/rollback observations are not represented as passed.

Machine-readable evidence is in `eval/results/official-link-verification-cp10-evidence.json`; offline metrics are in
`eval/results/security-v4-v2-report.json`.

## Handoff

```text
WP/Checkpoint: WP10 / CP10
Base commit SHA: 22d9dac5a4fa47d279896ebb98be1c99cbb15036 (completed CP9)
Dataset: security-v4-v2; 12 categories; SHA-256 69e93b7e6161989320fce7204606387bc54a50f693d311addd780b60de232748
Previous dataset: security-v4-v1 SHA unchanged at 19e8aa9f57d7930162159db3624169722896679fa210c3abf9805a5bf6412a7f
Offline gates: all pass; scope/component/resource/closure/grounding 100%; fabrication/OOS/not-found-malicious/SSRF
               bypass all zero; maximum cost US$0.008; p95 6.39 ms; budget exhaustion bounded partial
Hard case: Vietnamese input -> English query -> labeled official social announcement fixture -> bit.ly -> Google Form;
           VERIFIED, EXACT_RESOURCE, reference closure true, zero fabricated refs/URLs
Hosted tooling: strict reviewed-evidence validator plus real /api/v4 OIDC smoke; pending claims are rejected
Commands: CP10 focused 10 passed; backend 391 passed; Ruff pass; Alembic head 0018_remove_vector_compat;
          frontend 75 passed; lint/typecheck/build pass; production E2E 2 passed; equivalent cutover scan pass
Hosted status: pending; release_approved=false; all 11 hosted checks and five rollout/rollback windows still required
Known limitation: canonical npm run check:cutover is environment-blocked by Node 24.14.1 Unicode URL pathname
Required review: Tech lead and Security lead after reviewed hosted evidence is collected and validated
```

## Release boundary

- A passing offline report is not hosted evidence and does not approve release.
- The hosted validator requires every named check to be literally `passed`, reviewer attribution, timestamps and
  evidence references; it rejects missing, duplicate, pending and out-of-sequence claims.
- Hosted rollout evidence must follow `shadow -> visible -> enforced -> visible -> off`, with a positive observation
  window, samples, latency, cost, error rate and evidence reference for every stage.
- The hosted hard case must prove an actual official social source, short URL, third-party form, exact resource
  identity, reference closure and zero fabrication using a real v4 deployment and OIDC user token.
- Out-of-scope requests still terminate before provider/network/AI work; no-hit, provider failure or timeout never
  implies `SAFE` or `MALICIOUS`.
- No public v2/v3 route, general fact-check behavior or vector dependency was added.

The pre-existing deleted pytest session artifacts and generated Playwright last-run state were not included in WP10
ownership.
