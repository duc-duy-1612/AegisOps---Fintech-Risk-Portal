# Architecture Decision Record (ADR-001): AegisOps Production Deployment & Shared Persistence (Wave 4.1.1)

**Status:** Approved & Hardened in Wave 4.1.1 (Cloud Provisioning & Production Deploy deferred to Wave 4.2)  
**Target Platform:** Vercel Serverless (Next.js 15 App Router, Node.js Runtime, Region `sin1` Singapore)

---

## 1. Current Architecture (Baseline after Wave 3.1)
- **Runtime:** Next.js 15.1.7 App Router API Route Handlers on Node.js (`vercel.json` pinned to `sin1`, `maxDuration: 25s`).
- **State Store:** `serverSessionMap` (process-local JavaScript `Map`) + HMAC-SHA-256 signed `clientDelta` stored in browser `localStorage`.
- **Rate Limiting:** `rateBuckets` (process-local `Map` bounded to `2000` entries).
- **AI Engine:** Direct REST `fetch` calls to `gemini-2.5-flash` / `gemini-2.5-flash-lite` (7.5s–8s timeout, static 2-tier fallback).

## 2. Critical Infrastructure Limitations Addressed in Wave 4.1 & 4.1.1
1. **Cross-Instance State Divergence & Cold-Start Revocation Replay:** If serverless containers scale out or cold-start, `serverSessionMap` is empty. A stale browser holding a previously signed `APPROVED_ACTIVE` snapshot before a `REVOKED` action could replay the older snapshot into a fresh container because HMAC proves payload integrity, **not monotonicity across containers**.
2. **Upstash Redis REST `/pipeline` vs `/multi-exec` Atomicity:** Per Upstash REST API documentation (`https://upstash.com/docs/redis/features/restapi`), `/pipeline` only batches commands to save HTTP round-trips and is **not** atomic. Rate-limit `INCR` + `PEXPIRE NX` and distributed Gemini quota checks require `/multi-exec` (`MULTI`/`EXEC` atomic transaction) with per-command error validation.
3. **Serverless PostgreSQL Connection Amplification:** Using a fixed `Pool(max: 5)` across 40–100 concurrent Vercel serverless instances would open 200–500 database connections and exhaust PostgreSQL connection limits. Runtime instances must use Neon's pooled PgBouncer endpoint (`DATABASE_URL`) with `PG_POOL_MAX=1` (`allowExitOnIdle: true`), while DDL migrations use the direct endpoint (`DIRECT_URL`).
4. **HMAC Secret Rotation vs Persisted HITL Fingerprints:** Rotating `AEGIS_PII_HMAC_KEY` without dual-key fingerprint lineage would orphan active HITL feedback records and break duplicate detection during the rotation window.
5. **Project-Scoped Gemini Quota (RPM / TPM / RPD):** Because Google Gemini quotas are enforced per cloud project rather than per container instance, a purely local circuit breaker allows $N$ serverless instances to continue hammering an exhausted daily quota (`RPD`) or spend limit.

## 3. Proposed Architecture & Decisions

### Decision A — Authoritative State Persistence: PostgreSQL (`DATABASE_URL` Pooled + `DIRECT_URL` Migrations)
- **Chosen Option:** **Neon PostgreSQL (Singapore `aws-ap-southeast-1`)** accessed via `PostgresPersistenceAdapter`:
  - **Runtime (`DATABASE_URL`):** Pooled endpoint (`-pooler`) with `PG_POOL_MAX=1` default on serverless (`allowExitOnIdle: true`, `connectionTimeoutMillis: 4000`, `idleTimeoutMillis: 10000`). At 50 concurrent serverless instances, projected connections stay at $\le 50$ (well within a 100-connection budget).
  - **Migrations (`DIRECT_URL`):** Non-pooled direct endpoint for `sql/migrations/001_wave4_shared_persistence.sql` and `001_rollback.sql`.
  - **Transaction Lifecycle:** `BEGIN` $\to$ `SELECT ... FOR UPDATE` $\to$ revision & expiry check $\to$ guarded `INSERT ... ON CONFLICT (session_id) DO UPDATE WHERE state_revision = $expectedRevision AND status = 'ACTIVE' RETURNING state_revision` $\to$ monotonic HITL sync (`AND status <> 'REVOKED'`) $\to$ ledger/clawback unique-constraint guard (`SQLSTATE 23505` mapped to HTTP `409`) $\to$ `COMMIT` / `ROLLBACK`.

### Decision B — Atomic Distributed Rate Limiting: Upstash Redis REST `/multi-exec`
- **Chosen Option:** **Upstash Redis REST (`UPSTASH_REDIS_REST_URL` + `UPSTASH_REDIS_REST_TOKEN`)** using **`POST /multi-exec`** to execute `[["INCR", key], ["PEXPIRE", key, windowMs, "NX"]]` as an atomic Redis `MULTI`/`EXEC` transaction.
- **Validation & Fail-Closed Policy:** Inspects every command entry in the response array for `{ error }`, verifies integer counter $\ge 1$ and `PEXPIRE NX` flag $\in \{0, 1\}$, and fails closed (HTTP `503`) on both IP and Session counters whenever `AEGIS_REQUIRE_DISTRIBUTED_RATE_LIMIT=true` and Redis times out or errors.

### Decision C — Gemini Distributed Quota & Circuit Breaker Coordination
- Classify `429` (`RATE_LIMIT_RPM` vs `QUOTA_EXHAUSTED` for RPD/daily/spend limits), `503` (`OVERLOADED_503`), `TIMEOUT`, and `INVALID_API_KEY`.
- Perform **0 retries** on `QUOTA_EXHAUSTED` or `INVALID_API_KEY`; immediately open the local circuit breaker (`45s` cooldown) and broadcast `SET aegis:gemini:circuit:open <category> PX 45000` via Upstash `/multi-exec`.
- Enforce project-scoped global RPM (`GEMINI_GLOBAL_RPM_LIMIT=30`) and expensive Vision OCR RPM (`GEMINI_GLOBAL_OCR_RPM_LIMIT=12`, per-instance `MAX_CONCURRENT_VISION_OCR=2`) without ever caching raw receipt images or degrading core Fintech ledger readiness (`GET /api/health` stays HTTP `200` with `status: "degraded_ai"`).

## 4. Security, Secret Rotation & Data Compatibility Strategy
- New session tokens and PII pseudonyms always use the current primary secrets (`AEGIS_SESSION_SECRET`, `AEGIS_PII_HMAC_KEY`) and stamp non-reversible key version IDs (`hmacKeyVersion: "kid:<12-hex>"`).
- During the rotation window, `AEGIS_SESSION_SECRET_PREVIOUS` and `AEGIS_PII_HMAC_KEY_PREVIOUS` (`>= 32` chars) are accepted strictly for verification and HITL fingerprint lookup (`legacyTargetFingerprints`), preserving active HITL risk adjustments, duplicate prevention, cross-session isolation, and terminal `REVOKED`/`EXPIRED` states.
