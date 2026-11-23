# AegisOps Deployment, Database Migration & Operations Runbook (Wave 4.2)

> **Target Region:** Singapore (`sin1`) — aligned with low-latency Vietnam Fintech traffic and MoMo/SBV compliance locality.  
> **Scope Notice:** This runbook documents the exact steps required to provision cloud infrastructure, run SQL migrations via `DIRECT_URL`, configure pooled `DATABASE_URL` and Upstash `/multi-exec` rate limiting, rotate cryptographic keys without losing HITL compatibility, verify readiness probes, and roll back safely.

---

## 1. Prerequisites Checklist (Wave 4.2 Cloud Provisioning)

Before setting `AEGIS_REQUIRE_*` flags to `true` on Vercel Production/Preview:

1. **Neon PostgreSQL (Singapore `ap-southeast-1`)**
   - Provision a project & branch for `production` (and `staging`).
   - Copy **two** verified-TLS SSL connection strings (`sslmode=verify-full&channel_binding=require`):
     - `DATABASE_URL`: **Pooled** connection string (`ep-...-pooler.ap-southeast-1.aws.neon.tech/neondb?sslmode=verify-full&channel_binding=require`) for Vercel Serverless runtime (`PG_POOL_MAX=1`). The installed `pg@8.23.1` adapter enforces `{ rejectUnauthorized: true }` and sets `enableChannelBinding: true` explicitly (since `pg@8.23.1` ignores URL `channel_binding` unless `enableChannelBinding: true` is passed to `Pool`). Strict/production mode fails closed on missing `sslmode`, `sslmode=disable`, `require`, `verify-ca`, `prefer`, `no-verify`, `uselibpqcompat=true`, or `channel_binding=disable`.
     - `DIRECT_URL`: **Direct** non-pooled connection string (`ep-....ap-southeast-1.aws.neon.tech/neondb?sslmode=verify-full&channel_binding=require`) kept strictly in operator/migration tooling for DDL schema migrations and rollback (do **not** expose `DIRECT_URL` to normal Vercel Serverless runtime functions).
   - Enable Point-In-Time Recovery (PITR) retention >= 7 days.
2. **Upstash Redis (Singapore `ap-southeast-1`)**
   - Create a Regional Redis database (`Eviction` disabled, TLS enabled) supporting REST `/multi-exec` atomic transactions.
   - Copy `UPSTASH_REDIS_REST_URL` and `UPSTASH_REDIS_REST_TOKEN`.
3. **Google AI Studio / Gemini API Key**
   - Provision a paid/higher-RPM API key and configure project-scoped budgets (`GEMINI_GLOBAL_RPM_LIMIT=30`, `GEMINI_GLOBAL_OCR_RPM_LIMIT=12`).
4. **Cryptographic Secrets (Generate 4 distinct fresh 256-bit keys per environment)**
   ```bash
   openssl rand -hex 32   # -> AEGIS_SESSION_SECRET
   openssl rand -hex 32   # -> AEGIS_PII_HMAC_KEY
   openssl rand -hex 32   # -> AEGIS_DIAGNOSTICS_SECRET
   openssl rand -hex 32   # -> AEGIS_ADMIN_RESET_SECRET
   ```
   > **Domain Separation Policy:** All four secrets MUST be distinct (>= 32 chars) and unique per environment (Staging vs Production). `AEGIS_ADMIN_RESET_SECRET` never falls back to `AEGIS_SESSION_SECRET` and fails closed if unset, weak, or colliding with session/diagnostics/PII secrets.

---

## 2. Database Schema Migration & Verification (Using `DIRECT_URL`)

Always run schema DDL migrations against `DIRECT_URL` (non-pooled endpoint) before routing production traffic:

```bash
# 1. Verify direct connectivity
psql "$DIRECT_URL" -c "SELECT version(), current_database();"

# 2. Apply Wave 4 shared persistence DDL idempotently
psql "$DIRECT_URL" -v ON_ERROR_STOP=1 -f sql/migrations/001_wave4_shared_persistence.sql

# 3. Verify applied migration row & created tables
psql "$DIRECT_URL" -c "SELECT version, applied_at FROM aegis_schema_migrations;"
psql "$DIRECT_URL" -c "\dt aegis_*"
```

Expected tables:
- `aegis_schema_migrations`
- `aegis_workspace_sessions`
- `aegis_hitl_feedback`
- `aegis_ledger_transactions`
- `aegis_ledger_entries`
- `aegis_clawback_receipts`
- `aegis_audit_logs`

---

## 3. Vercel Environment Matrix

Set the following Environment Variables inside Vercel Project Settings (`Server-side` only — **NEVER** prefix with `NEXT_PUBLIC_`):

| Variable | Staging / Preview | Production | Notes |
| --- | --- | --- | --- |
| `AEGIS_SESSION_SECRET` | Fresh 64-hex secret | Fresh 64-hex secret | Distinct per environment |
| `AEGIS_PII_HMAC_KEY` | Fresh 64-hex secret | Fresh 64-hex secret | Keyed HMAC-SHA-256 PII pseudonymization (`kid:<12-hex>`; Law 91/2025/QH15 & Decree 356/2025/NĐ-CP) |
| `AEGIS_DIAGNOSTICS_SECRET` | Fresh 64-hex secret | Fresh 64-hex secret | Dedicated secret (`>=32` chars, distinct from session/admin secrets) for header `x-aegis-diagnostics-token` on `GET /api/health?diagnostics=internal` |
| `AEGIS_ADMIN_RESET_SECRET` | Fresh 64-hex secret | Fresh 64-hex secret | Dedicated secret (`>=32` chars, distinct from session/diagnostics/PII secrets) for admin Gemini circuit reset; fails closed if unset (zero fallback to `AEGIS_SESSION_SECRET`) |
| `AEGIS_ENABLE_DEMO_PERSONA_SWITCH` | `false` | `false` | Disables demo role switching in strict production mode |
| `AEGIS_PRODUCTION_STRICT_READINESS` | `true` | `true` | Enforces shared Postgres, Upstash Redis, strict secrets & project quota scope |
| `AEGIS_REQUIRE_STRICT_SECRETS` | `true` | `true` | Fail-closed HTTP 503 if missing/weak |
| `DATABASE_URL` | Staging `-pooler` URI (`?sslmode=verify-full&channel_binding=require`) | Production Neon `-pooler` URI (`?sslmode=verify-full&channel_binding=require`) | Runtime pooled verified-TLS connection (`rejectUnauthorized: true`, `enableChannelBinding: true`) |
| `DIRECT_URL` | Operator/CI migration vault only | Operator/CI migration vault only | Non-pooled verified-TLS URI for `psql` DDL migrations; omit from Vercel runtime functions |
| `PG_POOL_MAX` | `1` | `1` | Keeps 50 serverless instances $\le 50$ connections |
| `AEGIS_REQUIRE_SHARED_PERSISTENCE` | `true` | `true` | Disables in-memory cold-start fallback |
| `UPSTASH_REDIS_REST_URL` | Staging Upstash URL | Prod Upstash URL | Atomic `/multi-exec` (`INCR` + `PEXPIRE NX`) |
| `UPSTASH_REDIS_REST_TOKEN` | Staging Upstash Token | Prod Upstash Token | — |
| `AEGIS_REQUIRE_DISTRIBUTED_RATE_LIMIT` | `true` | `true` | Fail-closed HTTP 503 when Redis unavailable |
| `TRUST_PROXY_HEADERS` | `true` | `true` | Trusts Vercel `x-forwarded-for` / `x-real-ip` |
| `GEMINI_API_KEY` | Server API Key | Server Paid-Tier Key | Isolated via local + Redis circuit breaker (Paid Services terms required to prevent prompt training) |
| `GEMINI_QUOTA_SCOPE_ID` | Staging Google Project ID | Prod Google Project ID | Required in strict production mode (`proj_<24-hex>` project-level quota scope) |
| `GEMINI_PRIMARY_MODEL` | `gemini-3.5-flash-lite` | `gemini-3.5-flash-lite` | Primary Gemini Developer API model (`gemini-2.5-flash` auto-routes on 2026-12-01) |
| `GEMINI_FALLBACK_MODEL` | `gemini-2.5-flash-lite` | `gemini-2.5-flash-lite` | Secondary Gemini Developer API fallback model (active; distinct from Agent Platform/Vertex AI) |
| `AI_RATE_LIMIT_PER_MIN` | `30` | `60` | Per-route AI rate limit |
| `GEMINI_GLOBAL_RPM_LIMIT` | `30` | `60` | Global project RPM ceiling across containers |
| `GEMINI_GLOBAL_OCR_RPM_LIMIT` | `12` | `20` | Global Vision OCR RPM ceiling across containers |

---

## 4. Zero-Downtime Secret Rotation Procedure

To rotate `AEGIS_SESSION_SECRET` or `AEGIS_PII_HMAC_KEY` without breaking active cookies, stored `deltaIntegrityTag` records, or existing HITL target fingerprints:

1. Generate new primary secret (`NEW_KEY`).
2. Copy current active secret into `AEGIS_SESSION_SECRET_PREVIOUS` (or `AEGIS_PII_HMAC_KEY_PREVIOUS`).
3. Replace `AEGIS_SESSION_SECRET` (or `AEGIS_PII_HMAC_KEY`) with `NEW_KEY` in Vercel Env Vars and redeploy.
4. During the 24-hour rotation window:
   - New session tokens, delta integrity tags, and HITL feedback records are signed/hashed with `NEW_KEY` (stamping `hmacKeyVersion: "kid:<12-hex>"`).
   - Existing cookies, delta tags, and HITL target fingerprints created under `*_PREVIOUS` remain verifiable and searchable via dual-key lineage (`legacyTargetFingerprints`), while `REVOKED` and `EXPIRED` records remain permanently revoked/expired.
5. After > 24 hours (when 24h session cookies and default 24h HITL TTL window expire), clear `AEGIS_SESSION_SECRET_PREVIOUS` and `AEGIS_PII_HMAC_KEY_PREVIOUS`.

---

## 5. Health Probes & Go-Live Smoke Verification

After deployment finishes:

1. **Liveness Probe** (must return HTTP `200`, < 20ms):
   ```bash
   curl -fsS https://<domain>/api/health?probe=live
   ```
2. **Public Readiness Probe** (strictly redacted public response — must return HTTP `200` with `readinessOk: true`, `deploymentReadinessTier: "PRODUCTION_SHARED_INFRA_READY"`, and all boolean flags under `dependencies` equal to `true`):
   ```bash
   curl -fsS https://<domain>/api/health | jq .
   ```
3. **Authenticated Internal Diagnostics Probe** (returns `internalDiagnostics.persistence.mode: "POSTGRES"`, `rateLimiter.mode: "UPSTASH_REDIS"`, `sessionSecretMode: "CONFIGURED_ENV"`, `piiHmacMode: "CONFIGURED_ENV"`, and `aiModelConfig`; never pass token in URL query parameters):
   ```bash
   curl -fsS -H "x-aegis-diagnostics-token: $AEGIS_DIAGNOSTICS_SECRET" "https://<domain>/api/health?diagnostics=internal" | jq .
   ```
   > **Note:** Even if Gemini enters cooldown (`aiMode: "AI_COOLDOWN_DEGRADED"`), core Fintech ledger & compliance readiness remains HTTP `200` because deterministic fallback stays operational. HTTP `503` triggers strictly when Secrets, PostgreSQL, required Redis, quota scope, or strict demo-guard checks fail.

---

## 6. Receipt & Media Upload Payload Policy (Vercel 4.5 MB Default Boundary)

AegisOps enforces a conservative inline base64 JSON media contract on both `POST /api/merchant/vision` and `POST /api/sandbox` so supported receipt uploads remain safely below Vercel's default **4.5 MB** Serverless Function request-body limit without relying on the November 20, 2026 20 MiB Public Beta (which requires Fluid Compute, 4 GB Performance memory, and `VERCEL_SUPPORT_LARGE_REQUEST_BODY=1`):

- **Supported binary formats:** `image/png`, `image/jpeg`, `image/webp` (SVG is strictly rejected on Merchant Vision).
- **Maximum raw decoded image binary:** `3,000,000` bytes (decimal `3 MB`; `MAX_IMAGE_BINARY_BYTES`).
- **Maximum complete UTF-8 JSON request body:** `4,194,304` bytes (`4 MiB`; `MEDIA_MAX_JSON_BODY_BYTES`), leaving headroom below Vercel's 4.5 MB default limit after base64 expansion (`<= 4,000,064` chars) and JSON metadata.
- **Server-side enforcement:** Early strict `Content-Length` validation plus streamed UTF-8 byte counting (`readRequestBodyTextWithByteLimit`) that cancels oversized streams immediately and returns deterministic HTTP `413` (`code: "PAYLOAD_TOO_LARGE"`).
- **Client-side compression:** Images `<= 3,000,000` bytes are uploaded untouched; oversized supported images undergo bounded adaptive resizing/compression (max 6 attempts, quality floor `0.72`, no cropping) using native browser Canvas/ImageBitmap APIs. If an image still exceeds `3,000,000` bytes, the UI surfaces an actionable Vietnamese error without invoking Gemini.
- **Future option:** If larger receipts or multi-page documents are later required, adopt presigned direct client uploads (e.g., Vercel Blob) rather than raising inline JSON body limits prematurely.

---

## 7. Incident Rollback & Disaster Recovery

1. **Application Rollback:** Promote the previous known-good deployment inside Vercel (`Deployments -> Instant Rollback`).
2. **Database Backup & PITR:** Take a Neon branch snapshot before schema updates. To roll back Wave 4 schema cleanly in a pre-launch environment only:
   ```bash
   psql "$DIRECT_URL" -v ON_ERROR_STOP=1 -f sql/migrations/001_rollback.sql
   ```
3. **Session Emergency Revocation:** Call `DELETE /api/session` or set `status = 'REVOKED'` in `aegis_workspace_sessions` to immediately invalidate compromised demo sessions across all Vercel containers.

---

## 8. GitHub Actions CI Quality & Security Gate (`.github/workflows/ci.yml`)

The CI workflow runs on `push` and `pull_request` targeting `main`/`master` (`ubuntu-latest`, Node.js `24`) under strict read-only and external-AI isolation controls:

- **Least-Privilege Token (`CI-01`):** Top-level `permissions: { contents: read }` restricts `GITHUB_TOKEN` to read-only repository checkout; all other scopes default to `none`.
- **Production Dependency Audit (`CI-02`):** Runs read-only `npm audit --omit=dev` immediately after `npm ci` (failing on its real exit code; never invokes `npm audit fix` or suppresses findings).
- **Explicit E2E Gemini Isolation (`CI-03`):** The Playwright E2E step explicitly sets `AEGIS_E2E_DISABLE_EXTERNAL_AI: 'true'` and `GEMINI_API_KEY: ''` in addition to `playwright.config.ts` (`reuseExistingServer: false`), ensuring zero external Gemini API calls and zero GitHub Secrets required for CI.
- **Verification Status:** Workflow configuration is validated locally; remote GitHub Actions execution (`REMOTE_CI_NOT_VERIFIED`) and repository branch protection (`NOT_VERIFIED`) must be enabled and confirmed after an authorized Git push.
