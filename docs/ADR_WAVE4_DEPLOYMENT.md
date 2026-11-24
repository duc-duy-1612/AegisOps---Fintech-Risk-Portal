# Architecture Decision Record (ADR-001): AegisOps Production Deployment & Shared Persistence (Wave 4.1.1 — Reconciled Wave B0.1)

**Status:** Architecture Hardened in Code; Remote GitHub CI Passed (`Run #45337243148`), **No Cloud Infrastructure Provisioned or Verified Yet**
**Target Platform:** Vercel Serverless (Next.js `15.5.29` App Router, Node.js `24.x` Runtime per `package.json` `>=24.0.0 <25.0.0`, Region `sin1` Singapore, `maxDuration: 25s`)

---

## 1. Current Architecture Baseline (Reconciled Against Release `7fecff868ee24e572b2eae485049b72f86141aee`)
- **Runtime:** Next.js `15.5.29` App Router API Route Handlers on Node.js `24.x` (`vercel.json` pinned to `sin1`, `maxDuration: 25s`).
- **Local Fallback vs Shared Persistence:** Supports in-memory fallback (`serverSessionMap` + HMAC-SHA-256 signed `clientDelta`) for local dev/CI only, and `PostgresPersistenceAdapter` (`pg@8.23.1`) for shared PostgreSQL persistence when `DATABASE_URL` is configured or `AEGIS_REQUIRE_SHARED_PERSISTENCE=true`.
- **Rate Limiting:** Local bounded `rateBuckets` (`Map`, max `2000` entries) for dev/CI fallback, and Upstash Redis REST (`/multi-exec` + Lua `EVAL`) when `UPSTASH_REDIS_REST_URL`/`UPSTASH_REDIS_REST_TOKEN` are configured or `AEGIS_REQUIRE_DISTRIBUTED_RATE_LIMIT=true`.
- **AI Engine:** Direct REST `fetch` calls to Google Gemini Developer API with primary model `gemini-3.5-flash-lite`, secondary fallback model `gemini-2.5-flash-lite` (avoiding deprecated `gemini-2.5-flash` auto-routing on `2026-12-01`), and Deterministic Forensics Engine floor.
- **Authentication Boundary (Critical Disclosure):** No real OIDC/SSO IdP exists yet; `POST /api/session` issues HMAC-signed simulated demo persona cookies (`authMode: 'SIMULATED_DEMO_PERSONA'`). Maker and Checker identities are **not** independently authenticated.

## 2. Critical Infrastructure Limitations Addressed in Wave 4.1–4.2.1
1. **Cross-Instance State Divergence & Cold-Start Revocation Replay:** If serverless containers scale out or cold-start, process-local `serverSessionMap` is empty. A stale browser holding a previously signed `APPROVED_ACTIVE` snapshot before a `REVOKED` action could replay the older snapshot into a fresh container because HMAC proves payload integrity, **not monotonicity across containers**.
2. **Upstash Redis REST `/pipeline` vs `/multi-exec` & Atomic Lua `EVAL`:** Per Upstash REST API documentation (`https://upstash.com/docs/redis/features/restapi`), `/pipeline` only batches commands to save HTTP round-trips and is **not** atomic. Rate-limit `INCR` + `PEXPIRE NX` requires `/multi-exec` (`MULTI`/`EXEC` atomic transaction) with per-command error validation, while Gemini distributed circuit-gate checking + sliding-window RPM/OCR quota reservation and monotonic circuit updates require atomic Redis Lua `EVAL` execution (`ATOMIC_CIRCUIT_GATE_AND_QUOTA_RESERVE_LUA`, `ATOMIC_MONOTONIC_CIRCUIT_SET_LUA`).
3. **Serverless PostgreSQL Connection Amplification & Strict TLS:** Using a fixed `Pool(max: 5)` across 40–100 concurrent Vercel serverless instances would open 200–500 database connections and exhaust PostgreSQL connection limits. Runtime instances must use Neon's pooled PgBouncer endpoint (`DATABASE_URL`) with `PG_POOL_MAX=1` (`allowExitOnIdle: true`), strict `sslmode=verify-full`, `{ rejectUnauthorized: true }`, and explicit `enableChannelBinding: true`, while operator DDL migrations use the direct endpoint (`DIRECT_URL`).
4. **HMAC Secret Rotation vs Persisted HITL Fingerprints:** Rotating `AEGIS_PII_HMAC_KEY` without dual-key fingerprint lineage would orphan active HITL feedback records and break duplicate detection during the rotation window.
5. **Project-Scoped Gemini Quota (RPM / TPM / RPD) & Multi-Victim Clawbacks:** Google Gemini quotas are enforced per cloud project (`GEMINI_QUOTA_SCOPE_ID` -> `proj_<24-hex>`) rather than per API key or container instance, and multi-victim / partial clawbacks require Migration 002 schema support plus monotonic ledger status enforcement.

## 3. Proposed Architecture & Decisions

### Decision A — Authoritative State Persistence: PostgreSQL (`DATABASE_URL` Pooled + `DIRECT_URL` Migrations)
- **Chosen Option:** **Neon PostgreSQL (Singapore `aws-ap-southeast-1`)** accessed via `PostgresPersistenceAdapter` (`pg@8.23.1`) — *architecture approved; not yet provisioned*:
  - **Runtime (`DATABASE_URL`):** Pooled endpoint (`-pooler`) with `PG_POOL_MAX=1` default on serverless (`allowExitOnIdle: true`, `connectionTimeoutMillis: 4000`, `idleTimeoutMillis: 10000`). At 50 concurrent serverless instances, projected connections stay at $\le 50$ (well within a 100-connection budget).
  - **Strict TLS & Channel Binding:** Production/strict mode enforces `sslmode=verify-full`, strips URL SSL parameters after validation, sets `ssl: { rejectUnauthorized: true }`, and explicitly passes `enableChannelBinding: true` (failing closed on `disable`, `allow`, `prefer`, `require`, `verify-ca`, `no-verify`, `uselibpqcompat=true`, or `channel_binding=disable`).
  - **Operator DDL Migrations (`DIRECT_URL`):** Non-pooled direct endpoint (kept out of normal Vercel runtime functions) executing **both** required migrations in order:
    1. `sql/migrations/001_wave4_shared_persistence.sql`
    2. `sql/migrations/002_clawback_multi_victim_and_tx_status.sql` *(adds multi-victim/partial clawback columns `idempotency_key`, `victim_account_id`, `victim_owner_name`, `source_mule_account_id`, `original_tx_ids`, partial unique indexes `uq_aegis_clawback_session_idem` & `uq_aegis_clawback_session_reversal_tx`, lookup index `idx_aegis_clawback_session_alert`, and `BEFORE UPDATE` trigger `trg_aegis_ledger_tx_status_guard` / `aegis_guard_ledger_tx_status_transition()`).*
    - Rollbacks (reverse order, explicit authorization required): `sql/migrations/002_rollback.sql` (guarded against duplicate `(session_id, alert_id)` pairs) followed only on authorized full teardown by destructive `sql/migrations/001_rollback.sql`.
  - **Transaction Lifecycle:** `BEGIN` $\to$ `SELECT ... FOR UPDATE` $\to$ revision & expiry check $\to$ guarded `INSERT ... ON CONFLICT (session_id) DO UPDATE WHERE state_revision = $expectedRevision AND status = 'ACTIVE' RETURNING state_revision` $\to$ monotonic HITL sync (`AND status <> 'REVOKED'`) $\to$ guarded ledger/clawback upsert & unique-constraint checks (`SQLSTATE 23505` mapped to HTTP `409`) $\to$ append-only audit log insert $\to$ `COMMIT` / `ROLLBACK`.

### Decision B — Atomic Distributed Rate Limiting & Quota Coordination: Upstash Redis REST (`/multi-exec` + Lua `EVAL`)
- **Chosen Option:** **Upstash Redis REST (`UPSTASH_REDIS_REST_URL` + read-write `UPSTASH_REDIS_REST_TOKEN`)** — *architecture approved; not yet provisioned*:
  - **Rate Limiting:** Uses **`POST /multi-exec`** to execute `[["INCR", key], ["PEXPIRE", key, windowMs, "NX"]]` as an atomic Redis `MULTI`/`EXEC` transaction.
  - **Gemini Coordination:** Executes atomic Lua `EVAL` scripts (`ATOMIC_CIRCUIT_GATE_AND_QUOTA_RESERVE_LUA` and `ATOMIC_MONOTONIC_CIRCUIT_SET_LUA`) to combine 6-key circuit inspection with weighted sliding-window RPM/OCR reservation and monotonic circuit persistence, plus `/multi-exec` `DEL` for authorized admin resets.
  - **Validation & Fail-Closed Policy:** Inspects every command entry in the response array for `{ error }`, verifies integer counter $\ge 1$ and `PEXPIRE NX` flag $\in \{0, 1\}$, and fails closed (HTTP `503`) on both IP and Session counters whenever `AEGIS_REQUIRE_DISTRIBUTED_RATE_LIMIT=true` and Redis times out or errors.

### Decision C — Gemini Distributed Quota & Circuit Breaker Coordination
- Target **`gemini-3.5-flash-lite`** as primary (`thinkingConfig: { thinkingLevel: 'minimal' }`, `maxOutputTokens: 2048`) and **`gemini-2.5-flash-lite`** as secondary fallback (`temperature: 0.15`, `maxOutputTokens: 1024`), backed by the offline Deterministic Forensics Engine.
- Separate Google project quota identity (`GEMINI_QUOTA_SCOPE_ID` -> `proj_<24-hex>`) from credential identity (`GEMINI_API_KEY` -> `cred_<24-hex>`), so API key rotation clears retired `INVALID_API_KEY` latches without resetting project-level `RPD_EXHAUSTED` or `SPEND_LIMIT_EXHAUSTED` circuits.
- Enforce project-scoped global RPM (`GEMINI_GLOBAL_RPM_LIMIT`) and Vision OCR RPM (`GEMINI_GLOBAL_OCR_RPM_LIMIT`, per-instance `PER_INSTANCE_MAX_CONCURRENT_GEMINI=4` and `PER_INSTANCE_MAX_CONCURRENT_VISION_OCR=2`) without caching raw receipt images or degrading core Fintech ledger readiness (`GET /api/health` stays HTTP `200` with `status: "degraded_ai"`).

## 4. Security, Secret Rotation & Data Compatibility Strategy
- Maintain four cryptographically distinct `>= 32`-char secrets per environment: `AEGIS_SESSION_SECRET`, `AEGIS_PII_HMAC_KEY`, `AEGIS_DIAGNOSTICS_SECRET`, and `AEGIS_ADMIN_RESET_SECRET`.
- New session tokens and PII pseudonyms always use the current primary secrets (`AEGIS_SESSION_SECRET`, `AEGIS_PII_HMAC_KEY`) and stamp non-reversible key version IDs (`hmacKeyVersion: "kid:<12-hex>"`).
- During the rotation window, `AEGIS_SESSION_SECRET_PREVIOUS` and `AEGIS_PII_HMAC_KEY_PREVIOUS` (`>= 32` chars) are accepted strictly for verification and HITL fingerprint lookup (`legacyTargetFingerprints`), preserving active HITL risk adjustments, duplicate prevention, cross-session isolation, and terminal `REVOKED`/`EXPIRED` states.

## 5. Release Track Separation & Current Readiness Status

Remote GitHub Actions CI passed in local in-memory CI mode (`Run #45337243148` on commit `7fecff868ee24e572b2eae485049b72f86141aee`), **but no cloud infrastructure (Vercel, Neon, Upstash, or live Gemini quota) has been provisioned or verified yet**, and production authentication is **not** implemented. Deployment tracks must remain strictly separated:

### Track A — Protected Synthetic Demo
- Simulated demo personas remain enabled intentionally (`AEGIS_ENABLE_DEMO_PERSONA_SWITCH=true`).
- `AEGIS_PRODUCTION_STRICT_READINESS=false` *(required while demo persona switching is active; combining `true` with demo switching fails `/api/health` with HTTP `503`)*.
- Strict secrets (`AEGIS_REQUIRE_STRICT_SECRETS=true`), PostgreSQL shared persistence (`AEGIS_REQUIRE_SHARED_PERSISTENCE=true`), distributed rate limiting (`AEGIS_REQUIRE_DISTRIBUTED_RATE_LIMIT=true`), and strict Gemini quota scope (`AEGIS_REQUIRE_STRICT_GEMINI_QUOTA_SCOPE=true`) can and should be enabled independently.
- All accounts, wallets, ledgers, payments, and clawbacks remain **synthetic simulations**.
- Deployment **must** sit behind independently verified access protection (e.g., Vercel Deployment Protection) and **must not** be represented as genuine fintech production authentication.

### Track B — Genuine Public Production (Blocked Pending Authentication Engineering Wave)
- Requires genuine OIDC/SSO integration with an external Identity Provider (IdP) and MFA.
- Requires server-side trusted identity-to-role mapping (`L1_MAKER`, `L2_CHECKER`, `END_USER`).
- Requires independently authenticated Maker and Checker human principals (eliminating single-browser role switching).
- Requires `AEGIS_ENABLE_DEMO_PERSONA_SWITCH=false`.
- Requires `AEGIS_PRODUCTION_STRICT_READINESS=true` **only after** the real authentication flow has been implemented and verified.
- Remains **BLOCKED** until a separate authentication engineering and security validation wave is completed and independent production cloud infrastructure is provisioned and verified.
