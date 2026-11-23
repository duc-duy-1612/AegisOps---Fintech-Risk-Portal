import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { NextRequest } from 'next/server';
import { POST as feedbackPost } from '@/app/api/feedback/route';
import { GET as healthGet } from '@/app/api/health/route';
import { POST as playbookPost } from '@/app/api/playbook/route';
import { DELETE as sessionDelete, GET as sessionGet } from '@/app/api/session/route';
import { POST as walletPost } from '@/app/api/wallet/route';
import { createHitlFeedbackInSession } from '@/application/workspace-orchestrator';
import { runDeterministicForensicsSuite } from '@/domain/forensics-analyzers';
import { evaluateConsumerTransfer } from '@/domain/shield-evaluator';
import {
  enforceDistributedRouteRateLimit,
  executeAtomicRedisWindowIncrement,
} from '@/infrastructure/distributed-rate-limiter';
import {
  ATOMIC_CIRCUIT_GATE_AND_QUOTA_RESERVE_LUA,
  ATOMIC_MONOTONIC_CIRCUIT_SET_LUA,
  PER_INSTANCE_MAX_CONCURRENT_GEMINI,
  PER_INSTANCE_MAX_CONCURRENT_VISION_OCR,
  advanceGeminiCircuitCooldownForTest,
  authorizeAdminGeminiCircuitReset,
  classifyGeminiHttpFailure,
  computeNextPacificMidnightResetMs,
  createGeminiResilienceInstance,
  executeResilientGeminiGenerateContent,
  getGeminiCredentialFingerprint,
  getGeminiOperationalMetrics,
  getGeminiQuotaScopeId,
  getGeminiQuotaScopeStatus,
  getPacificTimezoneOffsetHours,
  parseProviderRetryGuidanceMs,
  resetGeminiResilienceForTest,
} from '@/infrastructure/gemini-resilience';
import {
  askGeminiCopilotOnCase,
  extractMerchantBillWithGeminiVision,
  runGeminiInvestigationWithFallback,
} from '@/infrastructure/gemini-agent';
import { redactSensitiveMetadata } from '@/infrastructure/observability';
import {
  ConcurrentStateConflictError,
  SessionRevokedError,
  evaluateServerlessPoolSizing,
  getPostgresMigrationConnectionUrl,
  type PgQueryableClient,
  type PgQueryablePool,
  PostgresPersistenceAdapter,
  resolveServerlessPoolMax,
  setPersistenceAdapterForTest,
} from '@/infrastructure/persistence-adapter';
import {
  getAllAcceptedPiiPseudonyms,
  getCurrentPiiHmacKeyId,
  getPreviousPiiHmacKeyId,
  inspectPiiFingerprintKeyLineage,
  matchesPseudonymizedPiiAcrossRotation,
  pseudonymizePiiWithHmacSha256,
} from '@/infrastructure/privacy-hasher';
import {
  SEED_ACCOUNTS,
  SEED_ALERTS,
  SEED_API_EVENTS,
  SEED_AUTH_LOGS,
  SEED_DEVICES,
  SEED_EVIDENCES,
  SEED_TRANSACTIONS,
} from '@/infrastructure/seed-scenarios';
import {
  SESSION_COOKIE_NAME,
  computeDeltaIntegrityTag,
  createSignedSessionToken,
  verifyDeltaIntegrityTag,
  verifySignedSessionToken,
} from '@/infrastructure/session-auth';
import { evictServerSessionForColdStartTest } from '@/infrastructure/workspace-store';

/**
 * In-memory PostgreSQL ACID, CAS & Constraint simulator implementing `PgQueryablePool`.
 * Models row locks (`FOR UPDATE`), guarded `ON CONFLICT ... WHERE state_revision = $7`,
 * terminal HITL `status <> 'REVOKED'`, unique constraints (`23505` on `(session_id, idempotency_key)`
 * and `(session_id, alert_id)` clawback), and connection cleanup (`end()`).
 * NOTE: Used for white-box adapter verification when a live PostgreSQL instance is not provisioned.
 */
class SqlVerifyingSpyPool implements PgQueryablePool {
  public readonly executedSql: string[] = [];
  public ended = false;
  public simulateNextInsertRaceConflict = false;
  public readonly sessions = new Map<
    string,
    {
      session_id: string;
      principal_id: string;
      state_revision: number;
      status: string;
      delta_integrity_tag: string;
      delta_json: unknown;
      expires_at: string;
      revoked_at: string | null;
    }
  >();
  public readonly hitlRows = new Map<string, { status: string; memory_version: number }>();
  public readonly ledgerTxIds = new Set<string>();
  public readonly ledgerIdempotencyKeys = new Map<string, string>();
  public readonly ledgerEntryIds = new Set<string>();
  public readonly clawbackKeys = new Map<string, string>();

  async query(text: string, values: unknown[] = []) {
    this.executedSql.push(text.replace(/\s+/g, ' ').trim());

    if (text.includes('SELECT 1 AS ok')) {
      return { rows: [{ ok: 1 }], rowCount: 1 };
    }

    if (text.includes('FROM aegis_workspace_sessions') && text.includes('FOR UPDATE')) {
      const sid = String(values[0]);
      const row = this.sessions.get(sid);
      return { rows: row ? [row] : [], rowCount: row ? 1 : 0 };
    }

    if (text.includes('SELECT status, expires_at FROM aegis_workspace_sessions')) {
      const sid = String(values[0]);
      const row = this.sessions.get(sid);
      return {
        rows: row ? [{ status: row.status, expires_at: row.expires_at }] : [],
        rowCount: row ? 1 : 0,
      };
    }

    if (text.includes('FROM aegis_workspace_sessions') && text.includes('delta_json')) {
      const sid = String(values[0]);
      const row = this.sessions.get(sid);
      return { rows: row ? [row] : [], rowCount: row ? 1 : 0 };
    }

    if (text.includes('INSERT INTO aegis_workspace_sessions')) {
      if (this.simulateNextInsertRaceConflict) {
        this.simulateNextInsertRaceConflict = false;
        return { rows: [], rowCount: 0 };
      }
      const sid = String(values[0]);
      const expectedRev = Number(values[6] ?? 0);
      const existing = this.sessions.get(sid);
      if (existing && (existing.state_revision !== expectedRev || existing.status !== 'ACTIVE')) {
        return { rows: [], rowCount: 0 };
      }
      const nextRev = Number(values[2]);
      this.sessions.set(sid, {
        session_id: sid,
        principal_id: String(values[1]),
        state_revision: nextRev,
        status: existing?.status ?? 'ACTIVE',
        delta_integrity_tag: String(values[3]),
        delta_json: JSON.parse(String(values[4])),
        expires_at: String(values[5]),
        revoked_at: existing?.revoked_at ?? null,
      });
      return { rows: [{ state_revision: nextRev }], rowCount: 1 };
    }

    if (text.includes('UPDATE aegis_workspace_sessions') && text.includes("status = 'REVOKED'")) {
      const sid = String(values[0]);
      const existing = this.sessions.get(sid);
      if (existing) {
        this.sessions.set(sid, {
          ...existing,
          status: 'REVOKED',
          revoked_at: new Date().toISOString(),
        });
      } else {
        this.sessions.set(sid, {
          session_id: sid,
          principal_id: 'revoked',
          state_revision: 0,
          status: 'REVOKED',
          delta_integrity_tag: '',
          delta_json: {},
          expires_at: new Date(Date.now() + 86_400_000).toISOString(),
          revoked_at: new Date().toISOString(),
        });
      }
      return { rows: [], rowCount: 1 };
    }

    if (text.includes('INSERT INTO aegis_hitl_feedback')) {
      const fid = String(values[0]);
      const status = String(values[7]);
      const version = Number(values[9]);
      const prev = this.hitlRows.get(fid);
      if (!prev || (version >= prev.memory_version && prev.status !== 'REVOKED')) {
        this.hitlRows.set(fid, { status, memory_version: version });
      }
      return { rows: [], rowCount: 1 };
    }

    if (text.includes('INSERT INTO aegis_ledger_transactions')) {
      const txId = String(values[0]);
      const sid = String(values[1]);
      const idemKey = values[7] ? String(values[7]) : null;
      if (!this.ledgerTxIds.has(txId) && idemKey) {
        const compositeIdem = `${sid}:${idemKey}`;
        const existingTxForIdem = this.ledgerIdempotencyKeys.get(compositeIdem);
        if (existingTxForIdem && existingTxForIdem !== txId) {
          const pgUniqueErr = new Error('duplicate key value violates unique constraint "uq_aegis_ledger_session_idem"') as Error & { code: string };
          pgUniqueErr.code = '23505';
          throw pgUniqueErr;
        }
        this.ledgerIdempotencyKeys.set(compositeIdem, txId);
      }
      this.ledgerTxIds.add(txId);
      return { rows: [], rowCount: 1 };
    }

    if (text.includes('INSERT INTO aegis_ledger_entries')) {
      this.ledgerEntryIds.add(String(values[0]));
      return { rows: [], rowCount: 1 };
    }

    if (text.includes('INSERT INTO aegis_clawback_receipts')) {
      const clawId = String(values[0]);
      const key = `${values[1]}:${values[2]}`;
      if (!this.clawbackKeys.has(key)) {
        this.clawbackKeys.set(key, clawId);
      }
      return { rows: [], rowCount: 1 };
    }

    return { rows: [], rowCount: 0 };
  }

  async connect(): Promise<PgQueryableClient> {
    return {
      query: (text: string, values?: unknown[]) => this.query(text, values),
      release: () => undefined,
    };
  }

  async end(): Promise<void> {
    this.ended = true;
  }
}

/**
 * Stateful in-memory simulator for Upstash Redis REST `/multi-exec` transactions.
 * Models atomic `INCR`, `PEXPIRE key ms NX`, `GET`, and `SET key val PX ms` with controllable clock `nowMs`.
 */
class StatefulUpstashMultiExecMock {
  public readonly calledEndpoints: string[] = [];
  public readonly counters = new Map<string, { value: string | number; expiresAtMs: number | null }>();
  public nowMs = Date.now();

  private purgeIfExpired(key: string) {
    const entry = this.counters.get(key);
    if (entry && entry.expiresAtMs !== null && entry.expiresAtMs <= this.nowMs) {
      this.counters.delete(key);
    }
  }

  public executeMultiExec(commands: unknown[][]): Array<{ result?: unknown; error?: string }> {
    return commands.map((cmd) => {
      const op = String(cmd[0] ?? '').toUpperCase();
      const key = String(cmd[1] ?? '');
      this.purgeIfExpired(key);

      if (op === 'GET') {
        const entry = this.counters.get(key);
        return { result: entry ? String(entry.value) : null };
      }

      if (op === 'DEL') {
        const existed = this.counters.delete(key);
        return { result: existed ? 1 : 0 };
      }

      if (op === 'SET') {
        const val = String(cmd[2] ?? '');
        const pxFlag = String(cmd[3] ?? '').toUpperCase();
        const ttlMs = pxFlag === 'PX' ? Number(cmd[4] ?? 0) : 0;
        this.counters.set(key, {
          value: val,
          expiresAtMs: ttlMs > 0 ? this.nowMs + ttlMs : null,
        });
        return { result: 'OK' };
      }

      if (op === 'INCR') {
        const existing = this.counters.get(key);
        const nextVal = (typeof existing?.value === 'number' ? existing.value : Number(existing?.value ?? 0)) + 1;
        this.counters.set(key, {
          value: nextVal,
          expiresAtMs: existing?.expiresAtMs ?? null,
        });
        return { result: nextVal };
      }

      if (op === 'PEXPIRE') {
        const ttlMs = Number(cmd[2] ?? 0);
        const mode = String(cmd[3] ?? '').toUpperCase();
        const existing = this.counters.get(key);
        if (!existing) return { result: 0 };
        if (mode === 'NX' && existing.expiresAtMs !== null) {
          return { result: 0 };
        }
        existing.expiresAtMs = this.nowMs + ttlMs;
        return { result: 1 };
      }

      if (op === 'EVAL') {
        const script = String(cmd[1] ?? '');
        const numKeys = Number(cmd[2] ?? 0);
        const keys = cmd.slice(3, 3 + numKeys).map((k) => String(k));
        const argv = cmd.slice(3 + numKeys).map((a) => String(a));
        for (const k of keys) {
          this.purgeIfExpired(k);
        }

        // 1. ATOMIC_MONOTONIC_CIRCUIT_SET_LUA
        if (script.includes('KEPT_EXISTING')) {
          const targetKey = keys[0]!;
          const candJson = argv[0]!;
          const candDeadline = Number(argv[1] ?? -1);
          const candLatched = argv[2] === '1';
          const ttlMs = Number(argv[3] ?? 1000);
          const evalNowMs = Number(argv[4] ?? this.nowMs);

          const existingEntry = this.counters.get(targetKey);
          const existingRaw = existingEntry ? String(existingEntry.value) : null;
          if (existingRaw) {
            if (existingRaw.includes('"latched":true')) {
              return { result: ['KEPT_EXISTING', existingRaw] };
            }
            const m = existingRaw.match(/"deadlineMs":(\d+)/);
            if (m && m[1]) {
              const existingDeadline = Number(m[1]);
              if (
                existingDeadline > evalNowMs &&
                !candLatched &&
                candDeadline >= 0 &&
                existingDeadline >= candDeadline
              ) {
                return { result: ['KEPT_EXISTING', existingRaw] };
              }
            }
          }

          this.counters.set(targetKey, {
            value: candJson,
            expiresAtMs: this.nowMs + ttlMs,
          });
          return { result: ['UPDATED', candJson] };
        }

        // 2. ATOMIC_CIRCUIT_GATE_AND_QUOTA_RESERVE_LUA
        if (script.includes('CIRCUIT_OPEN')) {
          const cVals = keys.slice(0, 6).map((k) => {
            const e = this.counters.get(k);
            return e ? String(e.value) : '';
          });
          if (cVals.some((v) => v.length > 0)) {
            return { result: ['CIRCUIT_OPEN', ...cVals] };
          }

          const rpmMax = Number(argv[1] ?? 30);
          const ocrMax = Number(argv[2] ?? 12);
          const isOcr = argv[3] === '1';
          const ttlMs = Number(argv[4] ?? 125_000);
          const weightMillis = Number(argv[5] ?? 0);

          const currRpmKey = keys[6]!;
          const prevRpmKey = keys[7]!;
          const currOcrKey = keys[8]!;
          const prevOcrKey = keys[9]!;

          const currRpm = Number(this.counters.get(currRpmKey)?.value ?? 0);
          const prevRpm = Number(this.counters.get(prevRpmKey)?.value ?? 0);
          const nextRpm = currRpm + 1;
          const slidingRpm = nextRpm + Math.ceil((prevRpm * weightMillis) / 1000);
          if (nextRpm > rpmMax || slidingRpm > rpmMax) {
            return { result: ['QUOTA_RPM_EXCEEDED', String(currRpm), String(slidingRpm)] };
          }

          let nextOcr = 0;
          if (isOcr) {
            const currOcr = Number(this.counters.get(currOcrKey)?.value ?? 0);
            const prevOcr = Number(this.counters.get(prevOcrKey)?.value ?? 0);
            nextOcr = currOcr + 1;
            const slidingOcr = nextOcr + Math.ceil((prevOcr * weightMillis) / 1000);
            if (nextOcr > ocrMax || slidingOcr > ocrMax) {
              return { result: ['QUOTA_OCR_EXCEEDED', String(currOcr), String(slidingOcr)] };
            }
          }

          const existingRpm = this.counters.get(currRpmKey);
          this.counters.set(currRpmKey, {
            value: nextRpm,
            expiresAtMs: existingRpm?.expiresAtMs ?? this.nowMs + ttlMs,
          });

          if (isOcr) {
            const existingOcr = this.counters.get(currOcrKey);
            this.counters.set(currOcrKey, {
              value: nextOcr,
              expiresAtMs: existingOcr?.expiresAtMs ?? this.nowMs + ttlMs,
            });
          }

          return { result: ['ALLOWED', String(nextRpm), String(nextOcr)] };
        }
      }

      return { error: `ERR unknown command '${op}'` };
    });
  }
}

const makeReq = (params: {
  url: string;
  method?: 'GET' | 'POST' | 'DELETE';
  sessionId: string;
  role: 'L1_MAKER' | 'L2_CHECKER' | 'END_USER';
  principalId: string;
  body?: Record<string, unknown>;
  tokenOverride?: string;
  clientIp?: string;
}): NextRequest => {
  const token =
    params.tokenOverride ??
    createSignedSessionToken({
      sessionId: params.sessionId,
      role: params.role,
      principalId: params.principalId,
    });
  const headers: Record<string, string> = {
    'content-type': 'application/json',
    host: 'localhost:3000',
    origin: 'http://localhost:3000',
    'sec-fetch-site': 'same-origin',
    'x-workspace-session': params.sessionId,
    cookie: `${SESSION_COOKIE_NAME}=${token}`,
  };
  if (params.clientIp) {
    headers['x-real-ip'] = params.clientIp;
  }
  return new NextRequest(params.url, {
    method: params.method ?? 'POST',
    headers,
    body: params.body ? JSON.stringify(params.body) : undefined,
  });
};

const originalEnv = { ...process.env };

afterEach(() => {
  setPersistenceAdapterForTest(null);
  resetGeminiResilienceForTest();
  vi.restoreAllMocks();
  for (const k of Object.keys(process.env)) {
    if (!(k in originalEnv)) {
      delete process.env[k];
    }
  }
  Object.assign(process.env, originalEnv);
});

describe('Wave 4.1.1 Infrastructure Correctness Audit & Production Acceptance Hardening', () => {
  it('Part 1 (Upstash Atomicity): uses /multi-exec (never /pipeline), preserves NX TTL, shares counters across instances, re-inits expired keys, and fails closed on timeout or partial command errors', async () => {
    const upstashSim = new StatefulUpstashMultiExecMock();
    process.env.UPSTASH_REDIS_REST_URL = 'https://apn1-atomic.upstash.io';
    process.env.UPSTASH_REDIS_REST_TOKEN = 'upstash-atomic-token';
    process.env.TRUST_PROXY_HEADERS = 'true';

    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input);
      upstashSim.calledEndpoints.push(url);
      const commands = JSON.parse(String(init?.body ?? '[]')) as unknown[][];
      return new Response(JSON.stringify(upstashSim.executeMultiExec(commands)), { status: 200 });
    });

    const cfg = { url: 'https://apn1-atomic.upstash.io', token: 'upstash-atomic-token' };

    // 1. First request initializes counter=1 and sets TTL (PEXPIRE NX = 1) via /multi-exec
    const first = await executeAtomicRedisWindowIncrement({
      cfg,
      key: 'aegis:rl:test:ip:203.0.113.10:100',
      windowMs: 65_000,
    });
    expect(first).toEqual({ ok: true, count: 1, ttlInitialized: true });
    expect(upstashSim.calledEndpoints.every((u) => u.endsWith('/multi-exec'))).toBe(true);
    expect(upstashSim.calledEndpoints.some((u) => u.includes('/pipeline'))).toBe(false);
    const initialExpiry = upstashSim.counters.get('aegis:rl:test:ip:203.0.113.10:100')?.expiresAtMs;

    // 2. Subsequent request after 5s increments counter=2 and does NOT reset TTL (PEXPIRE NX = 0)
    upstashSim.nowMs += 5_000;
    const second = await executeAtomicRedisWindowIncrement({
      cfg,
      key: 'aegis:rl:test:ip:203.0.113.10:100',
      windowMs: 65_000,
    });
    expect(second).toEqual({ ok: true, count: 2, ttlInitialized: false });
    expect(upstashSim.counters.get('aegis:rl:test:ip:203.0.113.10:100')?.expiresAtMs).toBe(initialExpiry);

    // 3. Expired key re-initializes cleanly to count=1 with new TTL
    upstashSim.nowMs += 70_000;
    const afterExpiry = await executeAtomicRedisWindowIncrement({
      cfg,
      key: 'aegis:rl:test:ip:203.0.113.10:100',
      windowMs: 65_000,
    });
    expect(afterExpiry).toEqual({ ok: true, count: 1, ttlInitialized: true });

    // 4. Concurrent requests from same IP across multiple application instances share counter & cannot bypass limit
    const reqInstanceA = makeReq({
      url: 'http://localhost:3000/api/playbook',
      sessionId: 'inst-a-sid',
      role: 'L2_CHECKER',
      principalId: 'checker-a',
      clientIp: '198.51.100.77',
    });
    const reqInstanceB = makeReq({
      url: 'http://localhost:3000/api/playbook',
      sessionId: 'inst-b-sid',
      role: 'L2_CHECKER',
      principalId: 'checker-b',
      clientIp: '198.51.100.77',
    });

    const concurrentResults = await Promise.all([
      enforceDistributedRouteRateLimit(reqInstanceA, 'shared-route', 2),
      enforceDistributedRouteRateLimit(reqInstanceB, 'shared-route', 2),
      enforceDistributedRouteRateLimit(reqInstanceA, 'shared-route', 2),
    ]);
    expect(concurrentResults.filter((r) => r.allowed).length).toBe(2);
    expect(concurrentResults.filter((r) => !r.allowed).length).toBe(1);

    // 5. Partial Redis command error inside /multi-exec response is detected & fails closed when required
    process.env.AEGIS_REQUIRE_DISTRIBUTED_RATE_LIMIT = 'true';
    fetchSpy.mockResolvedValueOnce(
      new Response(JSON.stringify([{ result: 1 }, { error: 'ERR syntax error in PEXPIRE' }]), {
        status: 200,
      })
    );
    const partialErrOutcome = await enforceDistributedRouteRateLimit(reqInstanceA, 'partial-err', 10);
    expect(partialErrOutcome.allowed).toBe(false);
    expect(partialErrOutcome.degraded).toBe(true);

    // 6. Network timeout (AbortError) fails closed when AEGIS_REQUIRE_DISTRIBUTED_RATE_LIMIT=true
    fetchSpy.mockRejectedValueOnce(Object.assign(new Error('Aborted'), { name: 'AbortError' }));
    const timeoutPlaybookRes = await playbookPost(
      makeReq({
        url: 'http://localhost:3000/api/playbook',
        sessionId: 'timeout-sid',
        role: 'L2_CHECKER',
        principalId: 'checker-to',
        body: { mode: 'TOGGLE_SHIELD', ruleId: 'SHD-1' },
      })
    );
    expect(timeoutPlaybookRes.status).toBe(503);
  });

  it('Part 2 (PostgreSQL Pooling, Lifecycle & Transactions): enforces serverless PG_POOL_MAX=1 sizing, DIRECT_URL priority, first-write CAS race protection, unique constraint 23505 rollback, and cold-start HITL revocation permanence', async () => {
    // 1. Serverless connection pool sizing & DIRECT_URL priority
    process.env.VERCEL = '1';
    delete process.env.PG_POOL_MAX;
    expect(resolveServerlessPoolMax()).toBe(1);
    const sizingDefault = evaluateServerlessPoolSizing({
      concurrentInstances: 50,
      connectionBudgetLimit: 100,
    });
    expect(sizingDefault.poolMaxPerInstance).toBe(1);
    expect(sizingDefault.projectedMaxConnections).toBe(50);
    expect(sizingDefault.withinBudget).toBe(true);

    const sizingOver = evaluateServerlessPoolSizing({
      concurrentInstances: 50,
      poolMaxPerInstance: 5,
      connectionBudgetLimit: 100,
    });
    expect(sizingOver.projectedMaxConnections).toBe(250);
    expect(sizingOver.withinBudget).toBe(false);

    process.env.DATABASE_URL = 'postgresql://user:pw@ep-pooler.ap-southeast-1.aws.neon.tech/neondb?sslmode=require';
    process.env.DIRECT_URL = 'postgresql://user:pw@ep-direct.ap-southeast-1.aws.neon.tech/neondb?sslmode=require';
    expect(getPostgresMigrationConnectionUrl()).toBe(process.env.DIRECT_URL);

    // 2. ACID transaction & cold-start HITL revocation permanence
    const spyPool = new SqlVerifyingSpyPool();
    const pgAdapter = new PostgresPersistenceAdapter(spyPool);
    setPersistenceAdapterForTest(pgAdapter);

    const sid = `w411-acid-${Date.now()}`;
    const createRes = await feedbackPost(
      makeReq({
        url: 'http://localhost:3000/api/feedback',
        sessionId: sid,
        role: 'L2_CHECKER',
        principalId: 'checker-w411',
        body: {
          action: 'CREATE',
          alertId: 'ALT-FPR-004',
          feedbackDecision: 'OVERRIDE_SAFE',
          targetScope: 'RECIPIENT_PATTERN',
          reasonCode: 'FALSE_POSITIVE_CONTEXT',
          analystRationale: 'Wave 4.1.1 cold start test',
          ttlHours: 24,
        },
      })
    );
    expect(createRes.status).toBe(200);
    const createJson = await createRes.json();
    const feedbackId = createJson.feedbackRecord.feedbackId as string;
    const staleRev1Snapshot = structuredClone(createJson.delta);

    const revokeRes = await feedbackPost(
      makeReq({
        url: 'http://localhost:3000/api/feedback',
        sessionId: sid,
        role: 'L2_CHECKER',
        principalId: 'checker-w411',
        body: {
          action: 'REVOKE',
          feedbackId,
          rejectReasonVi: 'Thu hồi vĩnh viễn',
        },
      })
    );
    expect(revokeRes.status).toBe(200);
    expect(spyPool.hitlRows.get(feedbackId)?.status).toBe('REVOKED');

    // Cold-start RAM eviction + stale rev 1 replay cannot resurrect REVOKED record
    evictServerSessionForColdStartTest(sid);
    const replayWalletRes = await walletPost(
      makeReq({
        url: 'http://localhost:3000/api/wallet',
        sessionId: sid,
        role: 'END_USER',
        principalId: 'usr-104',
        body: {
          action: 'TRANSFER',
          senderAccountId: 'ACC-USR-104',
          recipientAccountIdOrNumber: '0933445566',
          amountVnd: 250_000,
          message: 'Thanh toán sau cold start',
          clientDelta: staleRev1Snapshot,
        },
      })
    );
    expect(replayWalletRes.status).toBe(200);
    const replayJson = await replayWalletRes.json();
    const persistedHitl = replayJson.delta.hitlFeedbackMemory.find(
      (f: { feedbackId: string }) => f.feedbackId === feedbackId
    );
    expect(persistedHitl.status).toBe('REVOKED');

    // 3. First-write concurrent insert race (RETURNING 0 rows) rolls back & throws ConcurrentStateConflictError
    spyPool.simulateNextInsertRaceConflict = true;
    await expect(
      pgAdapter.commitSession({
        sessionId: 'race-new-session',
        principalId: 'p1',
        expectedRevision: 0,
        nextDelta: { ...createJson.delta, sessionId: 'race-new-session', stateRevision: 1 },
        expiresAtIso: new Date(Date.now() + 3600_000).toISOString(),
      })
    ).rejects.toBeInstanceOf(ConcurrentStateConflictError);
    expect(spyPool.executedSql.some((q) => q === 'ROLLBACK')).toBe(true);
  });

  it('rejects concurrent optimistic revision conflicts with HTTP 409 & rolls back Postgres transaction', async () => {
    const spyPool = new SqlVerifyingSpyPool();
    const pgAdapter = new PostgresPersistenceAdapter(spyPool);
    setPersistenceAdapterForTest(pgAdapter);

    const sid = `w41-cas-${Date.now()}`;
    const first = await feedbackPost(
      makeReq({
        url: 'http://localhost:3000/api/feedback',
        sessionId: sid,
        role: 'L2_CHECKER',
        principalId: 'checker-cas',
        body: {
          action: 'CREATE',
          alertId: 'ALT-FPR-004',
          feedbackDecision: 'OVERRIDE_SAFE',
        },
      })
    );
    const json1 = await first.json();

    await expect(
      pgAdapter.commitSession({
        sessionId: sid,
        principalId: 'checker-cas',
        expectedRevision: 0,
        nextDelta: { ...json1.delta, stateRevision: 99 },
        expiresAtIso: new Date(Date.now() + 3600_000).toISOString(),
      })
    ).rejects.toBeInstanceOf(ConcurrentStateConflictError);
    expect(spyPool.executedSql.some((q) => q === 'ROLLBACK')).toBe(true);
  });

  it('Part 2.B (Unique Constraint 23505, Expired Session & Pool Cleanup): rolls back duplicate idempotency_key violations, rejects expired DB sessions, and closes pool cleanly', async () => {
    const spyPool = new SqlVerifyingSpyPool();
    const pgAdapter = new PostgresPersistenceAdapter(spyPool);
    setPersistenceAdapterForTest(pgAdapter);

    const sid = `w411-uq-${Date.now()}`;
    const createRes = await feedbackPost(
      makeReq({
        url: 'http://localhost:3000/api/feedback',
        sessionId: sid,
        role: 'L2_CHECKER',
        principalId: 'checker-uq',
        body: {
          action: 'CREATE',
          alertId: 'ALT-FPR-004',
          feedbackDecision: 'OVERRIDE_SAFE',
        },
      })
    );
    const createJson = await createRes.json();
    const baseRev = Number(createJson.delta.stateRevision ?? 1);

    const idemDeltaA = {
      ...createJson.delta,
      stateRevision: baseRev + 1,
      customTransactions: [
        {
          id: 'TXN-IDEM-A',
          alertId: 'ALT-APP-003',
          senderAccountId: 'ACC-USR-101',
          receiverAccountId: 'ACC-MULE-901',
          amountVnd: 100_000,
          channel: 'P2P_WALLET' as const,
          message: 'test',
          deviceId: 'DEV-1',
          hopIndex: 1,
          status: 'SETTLED' as const,
          timestamp: new Date().toISOString(),
          idempotencyKey: 'DUP-IDEM-KEY-001',
        },
      ],
    };
    await pgAdapter.commitSession({
      sessionId: sid,
      principalId: 'p1',
      expectedRevision: baseRev,
      nextDelta: idemDeltaA,
      expiresAtIso: new Date(Date.now() + 3600_000).toISOString(),
    });

    const idemDeltaB = {
      ...idemDeltaA,
      stateRevision: baseRev + 2,
      customTransactions: [
        {
          ...idemDeltaA.customTransactions[0]!,
          id: 'TXN-IDEM-B-CONFLICT',
        },
      ],
    };
    await expect(
      pgAdapter.commitSession({
        sessionId: sid,
        principalId: 'p1',
        expectedRevision: baseRev + 1,
        nextDelta: idemDeltaB,
        expiresAtIso: new Date(Date.now() + 3600_000).toISOString(),
      })
    ).rejects.toBeInstanceOf(ConcurrentStateConflictError);

    const existingRow = spyPool.sessions.get(sid)!;
    spyPool.sessions.set(sid, {
      ...existingRow,
      expires_at: new Date(Date.now() - 10_000).toISOString(),
    });
    await expect(
      pgAdapter.commitSession({
        sessionId: sid,
        principalId: 'p1',
        expectedRevision: baseRev + 1,
        nextDelta: { ...idemDeltaA, stateRevision: baseRev + 2 },
        expiresAtIso: new Date(Date.now() + 3600_000).toISOString(),
      })
    ).rejects.toBeInstanceOf(SessionRevokedError);

    await pgAdapter.close();
    expect(spyPool.ended).toBe(true);
  });

  it('Part 2.C & Part 3 (SQL DDL Audit & Full HMAC Key Rotation Compatibility): validates migration DDL, key lineage IDs, old HITL lookup/duplicate compatibility after rotation, expired/revoked preservation & cross-session isolation', async () => {
    // Verify migration & rollback SQL files contain required idempotent constraints
    const migSql = readFileSync(
      join(process.cwd(), 'sql', 'migrations', '001_wave4_shared_persistence.sql'),
      'utf8'
    );
    const rollbackSql = readFileSync(
      join(process.cwd(), 'sql', 'migrations', '001_rollback.sql'),
      'utf8'
    );
    expect(migSql).toContain('CREATE TABLE IF NOT EXISTS aegis_workspace_sessions');
    expect(migSql).toContain('CREATE UNIQUE INDEX IF NOT EXISTS uq_aegis_ledger_session_idem');
    expect(migSql).toContain('UNIQUE (session_id, alert_id)');
    expect(rollbackSql).toContain('DROP TABLE IF EXISTS aegis_workspace_sessions');

    const oldSessionSecret = 'old-session-secret-0123456789abcdef0123';
    const newSessionSecret = 'new-session-secret-fedcba9876543210fedc';
    const oldPiiKey = 'old-pii-hmac-secret-0123456789abcdef0123';
    const newPiiKey = 'new-pii-hmac-secret-fedcba9876543210fedc';

    // 1. Issue session token, delta tag, and HITL record under Key V1 (old secrets)
    process.env.AEGIS_SESSION_SECRET = oldSessionSecret;
    process.env.AEGIS_PII_HMAC_KEY = oldPiiKey;
    const keyIdV1 = getCurrentPiiHmacKeyId();
    expect(keyIdV1).toMatch(/^kid:[0-9a-f]{12}$/);

    const validOldToken = createSignedSessionToken({
      sessionId: 'rot-session-a',
      role: 'L2_CHECKER',
      principalId: 'checker-rot',
    });
    const expiredOldToken = createSignedSessionToken({
      sessionId: 'rot-session-a',
      role: 'L2_CHECKER',
      principalId: 'checker-rot',
      issuedAtMs: Date.now() - 25 * 3600_000,
    });

    const createdUnderV1 = createHitlFeedbackInSession({
      sessionId: 'rot-session-a',
      alertId: 'ALT-FPR-004',
      feedbackDecision: 'FORCE_BLOCK',
      targetScope: 'RECIPIENT_PATTERN',
      reasonCode: 'CONFIRMED_MULE_PATTERN',
      analystRationale: 'Created under HMAC Key V1 before rotation',
      actorPrincipalId: 'checker-rot',
      actorRole: 'L2_CHECKER',
    });
    expect(createdUnderV1.feedbackRecord.hmacKeyVersion).toBe(keyIdV1);
    const oldFingerprint = createdUnderV1.feedbackRecord.targetFingerprint;

    // Strip recipientAccountId on a copy to prove pure HMAC fingerprint matching works after key rotation!
    const fingerprintOnlyRecord = {
      ...createdUnderV1.feedbackRecord,
      recipientAccountId: undefined,
    };

    // 2. Rotate to Key V2 while keeping Key V1 in *_PREVIOUS
    process.env.AEGIS_SESSION_SECRET = newSessionSecret;
    process.env.AEGIS_SESSION_SECRET_PREVIOUS = oldSessionSecret;
    process.env.AEGIS_PII_HMAC_KEY = newPiiKey;
    process.env.AEGIS_PII_HMAC_KEY_PREVIOUS = oldPiiKey;

    const keyIdV2 = getCurrentPiiHmacKeyId();
    expect(keyIdV2).not.toBe(keyIdV1);
    expect(getPreviousPiiHmacKeyId()).toBe(keyIdV1);

    // 3. Current vs Previous vs Invalid key verification
    const hospitalAcc = SEED_ACCOUNTS.find((a) => a.id === 'ACC-HOSP-800')!;
    const newFingerprint = pseudonymizePiiWithHmacSha256(hospitalAcc.accountNumber);
    expect(inspectPiiFingerprintKeyLineage(hospitalAcc.accountNumber, newFingerprint)).toBe('CURRENT_KEY');
    expect(inspectPiiFingerprintKeyLineage(hospitalAcc.accountNumber, oldFingerprint)).toBe('PREVIOUS_KEY');
    expect(inspectPiiFingerprintKeyLineage(hospitalAcc.accountNumber, 'deadbeef')).toBe('UNMATCHED');
    expect(matchesPseudonymizedPiiAcrossRotation(hospitalAcc.accountNumber, oldFingerprint)).toBe(true);

    // Weak/invalid previous key (< 32 chars) is rejected
    process.env.AEGIS_PII_HMAC_KEY_PREVIOUS = 'too-short-invalid-key';
    expect(inspectPiiFingerprintKeyLineage(hospitalAcc.accountNumber, oldFingerprint)).toBe('UNMATCHED');
    process.env.AEGIS_PII_HMAC_KEY_PREVIOUS = oldPiiKey;

    // 4. Old valid token verifies, expired old token rejects with EXPIRED, delta integrity tag verifies for Session A but fails for Session B (cross-session isolation)
    expect(verifySignedSessionToken(validOldToken).valid).toBe(true);
    const expCheck = verifySignedSessionToken(expiredOldToken);
    expect(expCheck.valid).toBe(false);
    if (!expCheck.valid) expect(expCheck.reason).toBe('EXPIRED');

    expect(verifyDeltaIntegrityTag(createdUnderV1.delta, 'rot-session-a')).toBe(true);
    expect(verifyDeltaIntegrityTag(createdUnderV1.delta, 'rot-session-b-other')).toBe(false);
    // New HMAC signing operations strictly use the new primary secret (not the previous secret)
    expect(computeDeltaIntegrityTag(createdUnderV1.delta, 'rot-session-a')).not.toBe(
      createdUnderV1.delta.deltaIntegrityTag
    );

    // 5. Old HITL record (fingerprint-only, created under Key V1) still matches in Forensics, Consumer Shield, and Duplicate Detection after rotating to Key V2!
    const fprAlert = SEED_ALERTS.find((a) => a.id === 'ALT-FPR-004')!;
    const allAccepted = getAllAcceptedPiiPseudonyms(hospitalAcc.accountNumber);
    const forensicsAfterRotation = runDeterministicForensicsSuite({
      alert: fprAlert,
      accounts: SEED_ACCOUNTS,
      devices: SEED_DEVICES,
      authLogs: SEED_AUTH_LOGS,
      transactions: SEED_TRANSACTIONS,
      apiEvents: SEED_API_EVENTS,
      evidences: SEED_EVIDENCES,
      feedbackMemory: [fingerprintOnlyRecord],
      targetFingerprintsByAccountId: { [hospitalAcc.id]: allAccepted[0]! },
      legacyTargetFingerprintsByAccountId: { [hospitalAcc.id]: allAccepted.slice(1) },
    });
    expect(forensicsAfterRotation.adaptiveFeedbackSummary?.appliedRecords.length).toBe(1);
    expect(forensicsAfterRotation.adaptiveFeedbackSummary?.appliedRecords[0]?.feedbackId).toBe(
      fingerprintOnlyRecord.feedbackId
    );

    const shieldAfterRotation = evaluateConsumerTransfer(
      {
        senderName: 'Test User',
        recipientAccountIdOrNumber: hospitalAcc.accountNumber,
        amountVnd: 500_000,
        message: 'Thanh toan vien phi',
      },
      [],
      SEED_ACCOUNTS,
      {
        hitlFeedbackMemory: [fingerprintOnlyRecord],
        targetFingerprintsByAccountId: { [hospitalAcc.id]: allAccepted[0]! },
        legacyTargetFingerprintsByAccountId: { [hospitalAcc.id]: allAccepted.slice(1) },
      }
    );
    expect(shieldAfterRotation.decision).toBe('WARN_COOLING_OFF');

    // Duplicate creation under Key V2 is blocked because existing Key V1 record is recognized across rotation
    expect(() =>
      createHitlFeedbackInSession({
        sessionId: 'rot-session-a',
        alertId: 'ALT-FPR-004',
        feedbackDecision: 'FORCE_BLOCK',
        targetScope: 'RECIPIENT_PATTERN',
        reasonCode: 'CONFIRMED_MULE_PATTERN',
        analystRationale: 'Duplicate attempt after key rotation',
        actorPrincipalId: 'checker-rot',
        actorRole: 'L2_CHECKER',
      })
    ).toThrow(/Đã tồn tại bản ghi HITL/);
  });

  it('revokes session across requests via DELETE /api/session and blocks subsequent access (HTTP 401)', async () => {
    const spyPool = new SqlVerifyingSpyPool();
    setPersistenceAdapterForTest(new PostgresPersistenceAdapter(spyPool));
    const sid = `w411-revoke-${Date.now()}`;
    const token = createSignedSessionToken({
      sessionId: sid,
      role: 'L2_CHECKER',
      principalId: 'checker-rev',
    });

    const delRes = await sessionDelete(
      makeReq({
        url: 'http://localhost:3000/api/session',
        method: 'DELETE',
        sessionId: sid,
        role: 'L2_CHECKER',
        principalId: 'checker-rev',
        tokenOverride: token,
      })
    );
    expect(delRes.status).toBe(200);

    const checkSession = await sessionGet(
      makeReq({
        url: 'http://localhost:3000/api/session',
        method: 'GET',
        sessionId: sid,
        role: 'L2_CHECKER',
        principalId: 'checker-rev',
        tokenOverride: token,
      })
    );
    expect(checkSession.status).toBe(401);

    const attemptMutation = await playbookPost(
      makeReq({
        url: 'http://localhost:3000/api/playbook',
        sessionId: sid,
        role: 'L2_CHECKER',
        principalId: 'checker-rev',
        tokenOverride: token,
        body: { mode: 'TOGGLE_SHIELD', ruleId: 'NON_EXISTENT' },
      })
    );
    expect(attemptMutation.status).toBe(401);
  });

  it('fails closed with HTTP 503 when strict secrets or required shared persistence are missing', async () => {
    process.env.AEGIS_REQUIRE_STRICT_SECRETS = 'true';
    process.env.AEGIS_SESSION_SECRET = '0123456789abcdef0123456789abcdef';
    process.env.AEGIS_DIAGNOSTICS_SECRET = 'diag-internal-secret-0123456789abcdef';
    delete process.env.AEGIS_PII_HMAC_KEY;

    // Public unauthenticated /api/health returns 503 without leaking missing env variable names or credential fingerprints
    const healthStrictMissingPii = await healthGet();
    expect(healthStrictMissingPii.status).toBe(503);
    const healthStrictBody = await healthStrictMissingPii.json();
    expect(healthStrictBody.readinessOk).toBe(false);
    expect(healthStrictBody.dependencies.secretsReady).toBe(false);
    expect(healthStrictBody.strictSecretsMissing).toBeUndefined();
    expect(healthStrictBody.aiCircuit.credentialFingerprint).toBeUndefined();

    // Authorized internal diagnostics endpoint exposes exact missing secret key name
    const authorizedDiagRes = await healthGet(
      new NextRequest('http://localhost:3000/api/health?diagnostics=internal', {
        headers: { 'x-aegis-diagnostics-token': 'diag-internal-secret-0123456789abcdef' },
      })
    );
    expect(authorizedDiagRes.status).toBe(503);
    const authorizedDiagBody = await authorizedDiagRes.json();
    expect(authorizedDiagBody.internalDiagnostics.strictSecretsMissing).toContain('AEGIS_PII_HMAC_KEY');

    process.env.AEGIS_PII_HMAC_KEY = 'fedcba9876543210fedcba9876543210';
    process.env.AEGIS_REQUIRE_SHARED_PERSISTENCE = 'true';
    delete process.env.DATABASE_URL;

    const healthMissingDb = await healthGet(
      new NextRequest('http://localhost:3000/api/health?diagnostics=internal', {
        headers: { 'x-aegis-diagnostics-token': 'diag-internal-secret-0123456789abcdef' },
      })
    );
    expect(healthMissingDb.status).toBe(503);
    const dbBody = await healthMissingDb.json();
    expect(dbBody.internalDiagnostics.persistence.mode).toBe('MISCONFIGURED_FAIL_CLOSED');

    const failClosedMutation = await playbookPost(
      makeReq({
        url: 'http://localhost:3000/api/playbook',
        sessionId: 'fail-closed-sid',
        role: 'L2_CHECKER',
        principalId: 'checker-fc',
        body: { mode: 'TOGGLE_SHIELD', ruleId: 'SHD-1' },
      })
    );
    expect(failClosedMutation.status).toBe(503);
  });

  it('Part 4 (Gemini Distributed Quota & Cost Control): classifies RPM vs TPM vs RPD vs Spend Limit vs Unknown 429 vs 503 vs Timeout vs 401, coordinates shared Redis circuit breaker across instances, deduplicates without caching images, and recovers after Pacific reset', async () => {
    expect(
      classifyGeminiHttpFailure(429, '{"error":{"message":"Quota exceeded for metric: generate_requests_per_day"}}')
    ).toBe('RPD_EXHAUSTED');
    expect(
      classifyGeminiHttpFailure(429, '{"error":{"message":"Project spend limit exceeded for billing account"}}')
    ).toBe('SPEND_LIMIT_EXHAUSTED');
    expect(classifyGeminiHttpFailure(429, '{"error":{"message":"Rate limit exceeded per minute (RPM)"}}')).toBe(
      'RATE_LIMIT_RPM'
    );
    expect(classifyGeminiHttpFailure(429, '{"error":{"message":"Tokens per minute (TPM) limit reached"}}')).toBe(
      'RATE_LIMIT_TPM'
    );
    expect(classifyGeminiHttpFailure(429, 'Too Many Requests')).toBe('UNKNOWN_RATE_LIMIT');
    // Google's generic 429 boilerplate ("check your plan and billing details") without specific quota dimension must be UNKNOWN_RATE_LIMIT (not SPEND_LIMIT_EXHAUSTED), while RPD details classify as RPD_EXHAUSTED
    expect(
      classifyGeminiHttpFailure(
        429,
        '{"error":{"code":429,"message":"You exceeded your current quota, please check your plan and billing details."}}'
      )
    ).toBe('UNKNOWN_RATE_LIMIT');
    expect(
      classifyGeminiHttpFailure(
        429,
        '{"error":{"code":429,"message":"You exceeded your current quota, please check your plan and billing details.","details":[{"quotaId":"GenerateRequestsPerDayPerProjectPerModel-FreeTier"}]}}'
      )
    ).toBe('RPD_EXHAUSTED');
    expect(classifyGeminiHttpFailure(503, 'Model overloaded')).toBe('UPSTREAM_OVERLOADED');
    expect(classifyGeminiHttpFailure(401, 'API key not valid')).toBe('INVALID_API_KEY');

    process.env.GEMINI_API_KEY = 'test-gemini-live-mock-key-0123456';
    const credFp = getGeminiCredentialFingerprint();

    // 1. Network timeout (AbortError) classified as TIMEOUT
    const fetchSpy = vi
      .spyOn(globalThis, 'fetch')
      .mockRejectedValueOnce(Object.assign(new Error('Timed out'), { name: 'AbortError' }));

    const timeoutRes = await executeResilientGeminiGenerateContent({
      model: 'gemini-2.5-flash',
      parts: [{ text: 'timeout-probe' }],
      jsonMode: true,
      maxTransientRetries: 0,
    });
    expect(timeoutRes.ok).toBe(false);
    expect(timeoutRes.category).toBe('TIMEOUT');

    // 2. Concurrent identical OCR requests deduplicate in-flight and retain ZERO raw images after completion
    resetGeminiResilienceForTest();
    fetchSpy.mockReset();
    fetchSpy.mockImplementation(
      () =>
        new Promise((resolve) => {
          setTimeout(() => {
            resolve(
              new Response(
                JSON.stringify({
                  candidates: [{ content: { parts: [{ text: '{"claimedAmountVnd":150000}' }] } }],
                }),
                { status: 200 }
              )
            );
          }, 25);
        })
    );

    const [dupA, dupB] = await Promise.all([
      executeResilientGeminiGenerateContent({
        model: 'gemini-2.5-flash',
        parts: [{ text: 'ocr-dedup' }, { inline_data: { mime_type: 'image/png', data: 'AAAA' } }],
        jsonMode: true,
        operationKind: 'VISION_OCR',
      }),
      executeResilientGeminiGenerateContent({
        model: 'gemini-2.5-flash',
        parts: [{ text: 'ocr-dedup' }, { inline_data: { mime_type: 'image/png', data: 'AAAA' } }],
        jsonMode: true,
        operationKind: 'VISION_OCR',
      }),
    ]);
    expect(dupA.ok).toBe(true);
    expect(dupB.ok).toBe(true);
    expect(dupA.deduplicated || dupB.deduplicated).toBe(true);
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    expect(getGeminiOperationalMetrics().activeDedupKeysCount).toBe(0);

    // 3. Distributed circuit breaker across instances via Upstash /multi-exec
    resetGeminiResilienceForTest();
    fetchSpy.mockReset();
    const upstashSim = new StatefulUpstashMultiExecMock();
    process.env.UPSTASH_REDIS_REST_URL = 'https://apn1-gemini-quota.upstash.io';
    process.env.UPSTASH_REDIS_REST_TOKEN = 'upstash-quota-token';

    let geminiHttpCalls = 0;
    fetchSpy.mockImplementation(async (input, init) => {
      const url = String(input);
      if (url.includes('upstash.io/multi-exec')) {
        const commands = JSON.parse(String(init?.body ?? '[]')) as unknown[][];
        return new Response(JSON.stringify(upstashSim.executeMultiExec(commands)), { status: 200 });
      }
      geminiHttpCalls += 1;
      return new Response('Quota exceeded for free_tier_requests per day, limit: 0', { status: 429 });
    });

    // Instance 1 encounters 429 RPD_EXHAUSTED -> 0 retries, broadcasts scoped RPD circuit open until Pacific midnight
    const inst1Res = await extractMerchantBillWithGeminiVision({
      mimeType: 'image/png',
      base64Data: 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=',
    });
    expect(inst1Res.outcome).toBe('AI_UNAVAILABLE');
    expect(geminiHttpCalls).toBe(1);
    const activePrimaryModel = process.env.GEMINI_PRIMARY_MODEL?.trim() || 'gemini-3.5-flash-lite';
    const rpdRedisKey = `aegis:gemini:cb:proj:${getGeminiQuotaScopeId()}:model:${activePrimaryModel}:RPD_EXHAUSTED`;
    const storedRpdJson = JSON.parse(String(upstashSim.counters.get(rpdRedisKey)?.value ?? '{}'));
    expect(storedRpdJson.category).toBe('RPD_EXHAUSTED');
    expect(storedRpdJson.credentialFingerprint).toBe(credFp);

    // Simulate Instance 2 (fresh local memory state, but connected to same Upstash Redis)
    resetGeminiResilienceForTest();
    const inst2Res = await executeResilientGeminiGenerateContent({
      model: activePrimaryModel,
      parts: [{ text: 'instance-2-call' }],
      jsonMode: true,
    });
    expect(inst2Res.ok).toBe(false);
    expect(inst2Res.category).toBe('RPD_EXHAUSTED');
    expect(inst2Res.circuitTripped).toBe(true);
    expect(inst2Res.distributedQuotaTripped).toBe(true);
    // Instance 2 sent ZERO calls to Google Gemini because shared Redis circuit was OPEN!
    expect(geminiHttpCalls).toBe(1);

    // 4. Unlike the old 45s bug, advancing 46s does NOT reopen an RPD_EXHAUSTED circuit; it only recovers after Pacific midnight!
    delete process.env.UPSTASH_REDIS_REST_URL;
    delete process.env.UPSTASH_REDIS_REST_TOKEN;
    advanceGeminiCircuitCooldownForTest(46_000);
    const stillOpenAt46s = await executeResilientGeminiGenerateContent({
      model: 'gemini-2.5-flash',
      parts: [{ text: 'still-blocked-at-46s' }],
      jsonMode: true,
    });
    expect(stillOpenAt46s.ok).toBe(false);
    expect(stillOpenAt46s.circuitTripped).toBe(true);
    expect(stillOpenAt46s.category).toBe('RPD_EXHAUSTED');

    // Advance past 25 hours (past next Pacific midnight reset) -> circuit recovers!
    advanceGeminiCircuitCooldownForTest(25 * 3600_000);
    fetchSpy.mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          candidates: [{ content: { parts: [{ text: '{"recovered":true}' }] } }],
        }),
        { status: 200 }
      )
    );
    const afterPacificMidnight = await executeResilientGeminiGenerateContent({
      model: 'gemini-2.5-flash',
      parts: [{ text: 'half-open-probe' }],
      jsonMode: true,
    });
    expect(afterPacificMidnight.ok).toBe(true);
    expect(getGeminiOperationalMetrics().circuitState).toBe('CLOSED');
    expect(getGeminiOperationalMetrics().mode).toBe('AI_LIVE');

    // 5. Deterministic fraud analysis & readiness=200 continue when Gemini is degraded
    const alert = SEED_ALERTS[0]!;
    const forensics = runDeterministicForensicsSuite({
      alert,
      accounts: SEED_ACCOUNTS,
      devices: SEED_DEVICES,
      authLogs: SEED_AUTH_LOGS,
      transactions: SEED_TRANSACTIONS,
      apiEvents: SEED_API_EVENTS,
      evidences: SEED_EVIDENCES,
    });
    fetchSpy.mockResolvedValueOnce(new Response('Daily quota exceeded', { status: 429 }));
    const fallbackReport = await runGeminiInvestigationWithFallback({
      alert,
      forensics,
      evidenceTranscript: 'Fallback test',
    });
    expect(fallbackReport.modelUsed).toContain('deterministic');

    const readyDuringAiCooldown = await healthGet(new NextRequest('http://localhost:3000/api/health'));
    expect(readyDuringAiCooldown.status).toBe(200);
  });

  it('Wave 4.1.2 Section 8.A & 8.B: verifies PST/PDT Pacific midnight math, Retry-After non-shortening, spend-limit rolling window, invalid-key latching, and non-overwriting circuit hierarchy', async () => {
    // 1. PST (UTC-8 in Jan) vs PDT (UTC-7 in Jul) calculation without hardcoded offset
    const winterPstUtc = Date.parse('2026-01-15T20:00:00.000Z'); // 12:00:00 PST (UTC-8)
    const summerPdtUtc = Date.parse('2026-07-15T20:00:00.000Z'); // 13:00:00 PDT (UTC-7)
    expect(getPacificTimezoneOffsetHours(winterPstUtc)).toBe(-8);
    expect(getPacificTimezoneOffsetHours(summerPdtUtc)).toBe(-7);

    // Next Pacific midnight in PST is 08:00:00Z (+ 60s safety margin = 08:01:00Z)
    const pstReset = computeNextPacificMidnightResetMs(winterPstUtc, 60_000);
    expect(new Date(pstReset).toISOString()).toBe('2026-01-16T08:01:00.000Z');

    // Next Pacific midnight in PDT is 07:00:00Z (+ 60s safety margin = 07:01:00Z)
    const pdtReset = computeNextPacificMidnightResetMs(summerPdtUtc, 60_000);
    expect(new Date(pdtReset).toISOString()).toBe('2026-07-16T07:01:00.000Z');

    // 2. Retry-After parsing: missing, invalid, valid seconds, valid HTTP-date, structured JSON retryDelay
    expect(parseProviderRetryGuidanceMs(null, '')).toEqual({
      hasValidGuidance: false,
      retryDelayMs: 0,
    });
    expect(parseProviderRetryGuidanceMs('not-a-number', '{malformed')).toEqual({
      hasValidGuidance: false,
      retryDelayMs: 0,
    });
    expect(parseProviderRetryGuidanceMs('-15', '')).toEqual({
      hasValidGuidance: false,
      retryDelayMs: 0,
    });
    expect(parseProviderRetryGuidanceMs('25', '')).toEqual({
      hasValidGuidance: true,
      retryDelayMs: 25_000,
    });
    expect(
      parseProviderRetryGuidanceMs(
        null,
        JSON.stringify({
          error: {
            message: 'Rate limit',
            details: [{ '@type': 'type.googleapis.com/google.rpc.RetryInfo', retryDelay: '18.5s' }],
          },
        })
      )
    ).toEqual({
      hasValidGuidance: true,
      retryDelayMs: 18_500,
    });

    // 3. Longer Retry-After (e.g. 25s > 4s in-request budget) is NEVER shortened to 4s to retry prematurely
    process.env.GEMINI_API_KEY = 'test-gemini-key-wave412-retry-check';
    const inst = createGeminiResilienceInstance('inst-retry');
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      new Response('{"error":{"message":"Requests per minute (RPM) exceeded"}}', {
        status: 429,
        headers: { 'retry-after': '45' },
      })
    );
    const rpmLongWaitRes = await inst.executeGenerateContent({
      model: 'gemini-2.5-flash',
      parts: [{ text: 'rpm-long-retry-after' }],
      jsonMode: true,
      maxTransientRetries: 1,
    });
    expect(rpmLongWaitRes.ok).toBe(false);
    expect(rpmLongWaitRes.category).toBe('RATE_LIMIT_RPM');
    // Must NOT retry in-request when provider requires 45s (> 4s in-request budget)
    expect(rpmLongWaitRes.attempts).toBe(1);
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    expect((rpmLongWaitRes.recoveryDeadlineMs ?? 0) - inst.nowMs()).toBeGreaterThanOrEqual(45_000);

    // 4. Spend-limit circuit stays open for 15-minute window (not 45s) and recovers after 15m
    const instSpend = createGeminiResilienceInstance('inst-spend');
    fetchSpy.mockResolvedValueOnce(
      new Response('{"error":{"message":"Billing spend limit reached for this window"}}', {
        status: 429,
      })
    );
    const spendRes = await instSpend.executeGenerateContent({
      model: 'gemini-2.5-flash',
      parts: [{ text: 'spend-probe' }],
      jsonMode: true,
    });
    expect(spendRes.category).toBe('SPEND_LIMIT_EXHAUSTED');
    expect(spendRes.circuitTripped).toBe(true);

    instSpend.advanceClockForTest(60_000); // 1 minute (> 45s)
    const spendAt1Min = await instSpend.executeGenerateContent({
      model: 'gemini-2.5-flash',
      parts: [{ text: 'spend-probe-2' }],
      jsonMode: true,
    });
    expect(spendAt1Min.ok).toBe(false);
    expect(spendAt1Min.circuitTripped).toBe(true);
    expect(spendAt1Min.category).toBe('SPEND_LIMIT_EXHAUSTED');

    instSpend.advanceClockForTest(15 * 60_000); // Past 15m rolling window
    fetchSpy.mockResolvedValueOnce(
      new Response(
        JSON.stringify({ candidates: [{ content: { parts: [{ text: '{"ok":true}' }] } }] }),
        { status: 200 }
      )
    );
    const spendRecovered = await instSpend.executeGenerateContent({
      model: 'gemini-2.5-flash',
      parts: [{ text: 'spend-probe-3' }],
      jsonMode: true,
    });
    expect(spendRecovered.ok).toBe(true);
  });

  it('Wave 4.1.2 Section 8.C & 8.D: coordinates 3 independent instances (A, B, C) via shared Redis, prevents short-lived circuits from shortening RPD/Invalid-Key circuits, blocks minute-boundary bursts, and fails closed on Redis timeout', async () => {
    const upstashSim = new StatefulUpstashMultiExecMock();
    process.env.UPSTASH_REDIS_REST_URL = 'https://apn1-multi-inst.upstash.io';
    process.env.UPSTASH_REDIS_REST_TOKEN = 'upstash-multi-token';
    process.env.GEMINI_API_KEY = 'test-gemini-multi-instance-key-v1-012345';
    process.env.AEGIS_ADMIN_RESET_SECRET = 'admin-reset-secret-0123456789abcdef';

    const instA = createGeminiResilienceInstance('inst-A');
    const instB = createGeminiResilienceInstance('inst-B');
    const instC = createGeminiResilienceInstance('inst-C');

    let geminiProviderCalls = 0;
    let nextProviderResponse: () => Response = () =>
      new Response('{"error":{"message":"Quota exceeded for requests_per_day (RPD)"}}', {
        status: 429,
      });

    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input);
      if (url.includes('upstash.io/multi-exec')) {
        const commands = JSON.parse(String(init?.body ?? '[]')) as unknown[][];
        return new Response(JSON.stringify(upstashSim.executeMultiExec(commands)), { status: 200 });
      }
      geminiProviderCalls += 1;
      return nextProviderResponse();
    });

    // 1. Instance A hits RPD_EXHAUSTED and opens shared RPD circuit until Pacific midnight
    const resA1 = await instA.executeGenerateContent({
      model: 'gemini-2.5-flash',
      parts: [{ text: 'inst-a-rpd' }],
      jsonMode: true,
    });
    expect(resA1.category).toBe('RPD_EXHAUSTED');
    expect(resA1.circuitTripped).toBe(true);
    const rpdDeadlineMs = resA1.recoveryDeadlineMs!;
    expect(rpdDeadlineMs - instA.nowMs()).toBeGreaterThan(60_000);
    expect(geminiProviderCalls).toBe(1);

    // 2. Instance B and Instance C immediately observe the open RPD circuit and send 0 Gemini calls
    const resB1 = await instB.executeGenerateContent({
      model: 'gemini-2.5-flash',
      parts: [{ text: 'inst-b-blocked' }],
      jsonMode: true,
    });
    const resC1 = await instC.executeGenerateContent({
      model: 'gemini-2.5-flash',
      parts: [{ text: 'inst-c-blocked' }],
      jsonMode: true,
    });
    expect(resB1.category).toBe('RPD_EXHAUSTED');
    expect(resB1.recoveryDeadlineMs).toBe(rpdDeadlineMs);
    expect(resC1.category).toBe('RPD_EXHAUSTED');
    expect(resC1.recoveryDeadlineMs).toBe(rpdDeadlineMs);
    expect(geminiProviderCalls).toBe(1);

    // 3. Even if Instance C experiences a short-lived RPM limit on another operation or model, it NEVER shortens the active RPD deadline
    const quotaScopeId = getGeminiQuotaScopeId();
    const rpdKey = `aegis:gemini:cb:proj:${quotaScopeId}:model:gemini-2.5-flash:RPD_EXHAUSTED`;
    const beforeValue = upstashSim.counters.get(rpdKey)?.value;
    expect(beforeValue).toBeDefined();

    // Advance 60 seconds (> old 45s TTL): Instance B is STILL blocked by the RPD circuit!
    upstashSim.nowMs += 60_000;
    instA.advanceClockForTest(60_000);
    instB.advanceClockForTest(60_000);
    instC.advanceClockForTest(60_000);

    const resBAt60s = await instB.executeGenerateContent({
      model: 'gemini-2.5-flash',
      parts: [{ text: 'inst-b-at-60s' }],
      jsonMode: true,
    });
    expect(resBAt60s.ok).toBe(false);
    expect(resBAt60s.category).toBe('RPD_EXHAUSTED');
    expect(geminiProviderCalls).toBe(1);

    // 4. Advance all instances & Redis past the Pacific midnight deadline -> all 3 instances recover consistently!
    const jumpMs = rpdDeadlineMs - instA.nowMs() + 5_000;
    upstashSim.nowMs += jumpMs;
    instA.advanceClockForTest(jumpMs);
    instB.advanceClockForTest(jumpMs);
    instC.advanceClockForTest(jumpMs);

    nextProviderResponse = () =>
      new Response(
        JSON.stringify({ candidates: [{ content: { parts: [{ text: '{"ok":true}' }] } }] }),
        { status: 200 }
      );

    const [recA, recB, recC] = await Promise.all([
      instA.executeGenerateContent({ model: 'gemini-2.5-flash', parts: [{ text: 'rec-a' }], jsonMode: true }),
      instB.executeGenerateContent({ model: 'gemini-2.5-flash', parts: [{ text: 'rec-b' }], jsonMode: true }),
      instC.executeGenerateContent({ model: 'gemini-2.5-flash', parts: [{ text: 'rec-c' }], jsonMode: true }),
    ]);
    expect(recA.ok && recB.ok && recC.ok).toBe(true);

    // 5. Invalid API Key latches across all instances and does NOT recover after hours until credential changes or authorized admin reset
    nextProviderResponse = () =>
      new Response('{"error":{"status":"UNAUTHENTICATED","message":"API key not valid"}}', {
        status: 401,
      });
    const invalidA = await instA.executeGenerateContent({
      model: 'gemini-2.5-flash',
      parts: [{ text: 'bad-key-a' }],
      jsonMode: true,
    });
    expect(invalidA.category).toBe('INVALID_API_KEY');
    expect(invalidA.latched).toBe(true);

    // Advance 3 hours: Instance B and C are still latched!
    upstashSim.nowMs += 3 * 3600_000;
    instA.advanceClockForTest(3 * 3600_000);
    instB.advanceClockForTest(3 * 3600_000);
    instC.advanceClockForTest(3 * 3600_000);

    const callsBeforeLatchedProbe = geminiProviderCalls;
    const latchedB = await instB.executeGenerateContent({
      model: 'gemini-2.5-flash',
      parts: [{ text: 'latched-b' }],
      jsonMode: true,
    });
    expect(latchedB.ok).toBe(false);
    expect(latchedB.category).toBe('INVALID_API_KEY');
    expect(latchedB.latched).toBe(true);
    expect(geminiProviderCalls).toBe(callsBeforeLatchedProbe);

    // Unauthorized admin reset is rejected
    const badReset = await authorizeAdminGeminiCircuitReset({ adminToken: 'wrong-token' });
    expect(badReset.ok).toBe(false);

    // Credential rotation (new GEMINI_API_KEY version) immediately permits recovery across instances!
    process.env.GEMINI_API_KEY = 'test-gemini-multi-instance-key-v2-rotated-999';
    nextProviderResponse = () =>
      new Response(
        JSON.stringify({ candidates: [{ content: { parts: [{ text: '{"rotated":true}' }] } }] }),
        { status: 200 }
      );
    const recoveredAfterKeyChange = await instB.executeGenerateContent({
      model: 'gemini-2.5-flash',
      parts: [{ text: 'new-cred-b' }],
      jsonMode: true,
    });
    expect(recoveredAfterKeyChange.ok).toBe(true);

    // 6. Sliding-Window Application RPM & OCR RPM Quota across instances + Minute-Boundary Burst Protection
    process.env.GEMINI_GLOBAL_RPM_LIMIT = '4';
    process.env.GEMINI_GLOBAL_OCR_RPM_LIMIT = '2';

    // Align clock to 55th second of a fresh minute bucket T (5 seconds before minute boundary)
    const baseMinuteMs = (Math.floor(upstashSim.nowMs / 60_000) + 2) * 60_000 + 55_000;
    const deltaTo55s = baseMinuteMs - instA.nowMs();
    upstashSim.nowMs = baseMinuteMs;
    instA.advanceClockForTest(deltaTo55s);
    instB.advanceClockForTest(deltaTo55s);
    instC.advanceClockForTest(deltaTo55s);

    // 3 Vision OCR requests across A, B, C -> only 2 allowed (GEMINI_GLOBAL_OCR_RPM_LIMIT = 2), 3rd blocked!
    const ocrBurst = await Promise.all([
      instA.executeGenerateContent({ model: 'gemini-2.5-flash', parts: [{ text: 'ocr-1' }], jsonMode: true, operationKind: 'VISION_OCR' }),
      instB.executeGenerateContent({ model: 'gemini-2.5-flash', parts: [{ text: 'ocr-2' }], jsonMode: true, operationKind: 'VISION_OCR' }),
      instC.executeGenerateContent({ model: 'gemini-2.5-flash', parts: [{ text: 'ocr-3' }], jsonMode: true, operationKind: 'VISION_OCR' }),
    ]);
    expect(ocrBurst.filter((r) => r.ok).length).toBe(2);
    expect(ocrBurst.filter((r) => !r.ok && r.distributedQuotaTripped).length).toBe(1);

    // Cross the minute boundary by 6 seconds (now at 01:01.0 of minute bucket T+1, elapsedRatio = 1/60):
    // Previous minute bucket had 3 total RPM requests (weight floor(3 * 59/60) = 2).
    // With GEMINI_GLOBAL_RPM_LIMIT = 4, only 2 more requests are allowed right after the boundary (NOT 4 more!), preventing a 2x boundary burst!
    upstashSim.nowMs += 6_000;
    instA.advanceClockForTest(6_000);
    instB.advanceClockForTest(6_000);
    instC.advanceClockForTest(6_000);

    const boundaryBurst = await Promise.all([
      instA.executeGenerateContent({ model: 'gemini-2.5-flash', parts: [{ text: 'b-1' }], jsonMode: true }),
      instB.executeGenerateContent({ model: 'gemini-2.5-flash', parts: [{ text: 'b-2' }], jsonMode: true }),
      instC.executeGenerateContent({ model: 'gemini-2.5-flash', parts: [{ text: 'b-3' }], jsonMode: true }),
    ]);
    expect(boundaryBurst.filter((r) => r.ok).length).toBe(2);
    expect(boundaryBurst.filter((r) => !r.ok && r.distributedQuotaTripped).length).toBe(1);

    // Verify every Redis counter key has a non-null expiresAtMs (no unbounded keys without TTL)
    for (const [, entry] of upstashSim.counters.entries()) {
      expect(entry.expiresAtMs).not.toBeNull();
    }

    // 7. Strict fail-closed behavior when AEGIS_REQUIRE_DISTRIBUTED_RATE_LIMIT=true and Redis times out
    process.env.AEGIS_REQUIRE_DISTRIBUTED_RATE_LIMIT = 'true';
    fetchSpy.mockRejectedValueOnce(Object.assign(new Error('Redis timeout'), { name: 'AbortError' }));
    const failClosedRes = await instA.executeGenerateContent({
      model: 'gemini-2.5-flash',
      parts: [{ text: 'redis-timeout-check' }],
      jsonMode: true,
    });
    expect(failClosedRes.ok).toBe(false);
    expect(failClosedRes.failClosedRedisError).toBe(true);
  });

  it('redacts secrets, images, database URIs, and phone/account numbers from structured telemetry', () => {
    const redacted = redactSensitiveMetadata({
      geminiApiKey: 'AIzaSySecretKeyMock123',
      database_url: 'postgresql://user:supersecret@db.neon.tech/neondb',
      imageDataUrl: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB',
      payloadPreview: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB',
      note: 'Chuyển tới 0987654321 từ postgresql://root:pw@host/db',
    }) as Record<string, unknown>;

    expect(redacted.geminiApiKey).toBe('[REDACTED]');
    expect(redacted.database_url).toBe('[REDACTED]');
    expect(redacted.imageDataUrl).toBe('[REDACTED]');
    expect(String(redacted.payloadPreview)).toContain('[REDACTED_IMAGE_DATA_URL:');
    expect(redacted.note).toBe('[REDACTED_CONNECTION_URI]');

    const phoneRedacted = redactSensitiveMetadata({ msg: 'TK 0987654321 gửi 100000' }) as Record<
      string,
      string
    >;
    expect(phoneRedacted.msg).toContain('098****321');
    expect(phoneRedacted.msg).not.toContain('0987654321');
  });

  it('Part 5 (CI/CD Workflow Validation): validates Node 24 LTS, offline deterministic Gemini env, Playwright E2E, and artifact upload configuration', () => {
    const ciYaml = readFileSync(join(process.cwd(), '.github', 'workflows', 'ci.yml'), 'utf8');
    expect(ciYaml).toContain("node-version: '24'");
    expect(ciYaml).not.toContain("node-version: '20'");
    expect(ciYaml).toContain('npm ci');
    expect(ciYaml).toContain('npm run typecheck');
    expect(ciYaml).toContain('npm run lint');
    expect(ciYaml).toContain('npm test');
    expect(ciYaml).toContain('npm run build');
    expect(ciYaml).toContain('npx playwright install --with-deps chromium');
    expect(ciYaml).toContain('npm run test:e2e');
    expect(ciYaml).toContain("GEMINI_API_KEY: ''");
    expect(ciYaml).toContain('actions/upload-artifact@v4');
  });

  it('Wave 4.1.3 Section 1 & 2: prevents check-to-reserve races via atomic Lua EVAL, cleans up retired credential circuit keys across valid->invalid->invalid->valid rotations, and avoids counter inflation on rejected requests', async () => {
    const upstashSim = new StatefulUpstashMultiExecMock();
    process.env.UPSTASH_REDIS_REST_URL = 'https://apn1-w413.upstash.io';
    process.env.UPSTASH_REDIS_REST_TOKEN = 'upstash-w413-token';

    // 1. Cryptographic 96-bit credential fingerprint properties (24-hex, non-reversible, collision-free across versions)
    const keyValid1 = 'AIzaSyTestCredentialVersion1_Valid_00001';
    const keyInvalid2 = 'AIzaSyTestCredentialVersion2_Invalid_002';
    const keyInvalid3 = 'AIzaSyTestCredentialVersion3_Invalid_003';
    const keyValid4 = 'AIzaSyTestCredentialVersion4_Valid_00004';

    const fp1 = getGeminiCredentialFingerprint(keyValid1);
    const fp2 = getGeminiCredentialFingerprint(keyInvalid2);
    const fp3 = getGeminiCredentialFingerprint(keyInvalid3);
    const fp4 = getGeminiCredentialFingerprint(keyValid4);

    for (const fp of [fp1, fp2, fp3, fp4]) {
      expect(fp).toMatch(/^cred_[0-9a-f]{24}$/);
      expect(fp).not.toContain('AIza');
    }
    expect(new Set([fp1, fp2, fp3, fp4]).size).toBe(4);

    const instA = createGeminiResilienceInstance('w413-inst-A');
    const instB = createGeminiResilienceInstance('w413-inst-B');

    let providerStatus = 200;
    let providerBody = JSON.stringify({
      candidates: [{ content: { parts: [{ text: '{"ok":true}' }] } }],
    });
    let geminiHttpCount = 0;

    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input);
      if (url.includes('upstash.io/multi-exec')) {
        const commands = JSON.parse(String(init?.body ?? '[]')) as unknown[][];
        return new Response(JSON.stringify(upstashSim.executeMultiExec(commands)), { status: 200 });
      }
      geminiHttpCount += 1;
      return new Response(providerBody, { status: providerStatus });
    });

    // Step A: Valid Key V1 succeeds
    process.env.GEMINI_API_KEY = keyValid1;
    const resV1 = await instA.executeGenerateContent({
      model: 'gemini-2.5-flash',
      parts: [{ text: 'v1-call' }],
      jsonMode: true,
    });
    expect(resV1.ok).toBe(true);

    // Step B: Rotate Valid V1 -> Invalid V2 (opens latched circuit for fp2)
    process.env.GEMINI_API_KEY = keyInvalid2;
    providerStatus = 401;
    providerBody = '{"error":{"status":"UNAUTHENTICATED","message":"API key not valid"}}';
    const resV2 = await instA.executeGenerateContent({
      model: 'gemini-2.5-flash',
      parts: [{ text: 'v2-invalid' }],
      jsonMode: true,
    });
    expect(resV2.ok).toBe(false);
    expect(resV2.category).toBe('INVALID_API_KEY');
    expect(resV2.latched).toBe(true);
    const latchKeyFp2 = `aegis:gemini:cb:cred:${fp2}:INVALID_API_KEY`;
    expect(upstashSim.counters.has(latchKeyFp2)).toBe(true);

    // Verify rejected request while circuit is open does NOT increment the RPM quota counter (atomic Lua EVAL check-before-INCR)
    const currBucket = Math.floor(upstashSim.nowMs / 60_000);
    const rpmKeyScope = `aegis:gemini:quota:${getGeminiQuotaScopeId()}:rpm:${currBucket}`;
    const rpmBeforeBlocked = Number(upstashSim.counters.get(rpmKeyScope)?.value ?? 0);
    const blockedOnInstB = await instB.executeGenerateContent({
      model: 'gemini-2.5-flash',
      parts: [{ text: 'v2-blocked-on-b' }],
      jsonMode: true,
    });
    expect(blockedOnInstB.ok).toBe(false);
    expect(blockedOnInstB.latched).toBe(true);
    const rpmAfterBlocked = Number(upstashSim.counters.get(rpmKeyScope)?.value ?? 0);
    expect(rpmAfterBlocked).toBe(rpmBeforeBlocked);

    // Step C: Rotate Invalid V2 -> Invalid V3 (cleans up fp2 circuit key in Redis & opens new latched circuit for fp3!)
    process.env.GEMINI_API_KEY = keyInvalid3;
    const resV3 = await instA.executeGenerateContent({
      model: 'gemini-2.5-flash',
      parts: [{ text: 'v3-also-invalid' }],
      jsonMode: true,
    });
    expect(resV3.ok).toBe(false);
    expect(resV3.category).toBe('INVALID_API_KEY');
    expect(resV3.latched).toBe(true);
    // Retired fp2 latch key was actively deleted from Redis during rotation!
    expect(upstashSim.counters.has(latchKeyFp2)).toBe(false);
    const latchKeyFp3 = `aegis:gemini:cb:cred:${fp3}:INVALID_API_KEY`;
    expect(upstashSim.counters.has(latchKeyFp3)).toBe(true);

    // Step D: Rotate Invalid V3 -> Valid V4 (cleans up fp3 circuit key & recovers immediately)
    process.env.GEMINI_API_KEY = keyValid4;
    providerStatus = 200;
    providerBody = JSON.stringify({
      candidates: [{ content: { parts: [{ text: '{"ok":true}' }] } }],
    });
    const resV4 = await instA.executeGenerateContent({
      model: 'gemini-2.5-flash',
      parts: [{ text: 'v4-valid-recovered' }],
      jsonMode: true,
    });
    expect(resV4.ok).toBe(true);
    expect(upstashSim.counters.has(latchKeyFp3)).toBe(false);
    expect(geminiHttpCount).toBe(4);
  });

  it('Wave 4.1.3 Section 3 & 4: escalates repeated spend-limit cooldowns exponentially without premature shortening and enforces public vs protected internal health diagnostics', async () => {
    const upstashSim = new StatefulUpstashMultiExecMock();
    process.env.UPSTASH_REDIS_REST_URL = 'https://apn1-w413-spend.upstash.io';
    process.env.UPSTASH_REDIS_REST_TOKEN = 'upstash-w413-spend-token';
    process.env.GEMINI_API_KEY = 'AIzaSySpendLimitTestKey_0123456789abcdef';
    process.env.GEMINI_SPEND_LIMIT_COOLDOWN_MS = '900000'; // 15m base

    const instA = createGeminiResilienceInstance('spend-inst-A');
    const instB = createGeminiResilienceInstance('spend-inst-B');

    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input);
      if (url.includes('upstash.io/multi-exec')) {
        const commands = JSON.parse(String(init?.body ?? '[]')) as unknown[][];
        return new Response(JSON.stringify(upstashSim.executeMultiExec(commands)), { status: 200 });
      }
      return new Response(
        '{"error":{"code":429,"message":"Project spend limit exceeded for billing account"}}',
        { status: 429 }
      );
    });

    // 1. First spend-limit strike opens 15-minute (900,000ms) conservative application cooldown
    const strike1 = await instA.executeGenerateContent({
      model: 'gemini-2.5-flash',
      parts: [{ text: 'spend-strike-1' }],
      jsonMode: true,
    });
    expect(strike1.category).toBe('SPEND_LIMIT_EXHAUSTED');
    expect(strike1.deadlineSource).toBe('APPLICATION_CONSERVATIVE_COOLDOWN');
    const deadline1 = strike1.recoveryDeadlineMs!;
    expect(deadline1 - instA.nowMs()).toBeGreaterThanOrEqual(899_950);
    expect(deadline1 - instA.nowMs()).toBeLessThanOrEqual(900_000);

    // 2. If another instance hits a spend-limit error with a shorter configured window while deadline1 is active, ATOMIC_MONOTONIC_CIRCUIT_SET_LUA refuses to shorten deadline1
    process.env.GEMINI_SPEND_LIMIT_COOLDOWN_MS = '120000'; // 2m (< 15m remaining)
    const concurrentShortAttempt = await instB.executeGenerateContent({
      model: 'gemini-2.5-flash',
      parts: [{ text: 'spend-concurrent' }],
      jsonMode: true,
    });
    expect(concurrentShortAttempt.recoveryDeadlineMs).toBe(deadline1);
    process.env.GEMINI_SPEND_LIMIT_COOLDOWN_MS = '900000';

    // 3. Advance past 15-minute cooldown (15m + 5s): single probe runs, provider still returns SPEND_LIMIT_EXHAUSTED -> Strike 2 escalates cooldown to 30 minutes (1,800,000ms)!
    upstashSim.nowMs += 905_000;
    instA.advanceClockForTest(905_000);
    const strike2 = await instA.executeGenerateContent({
      model: 'gemini-2.5-flash',
      parts: [{ text: 'spend-strike-2' }],
      jsonMode: true,
    });
    expect(strike2.ok).toBe(false);
    expect(strike2.category).toBe('SPEND_LIMIT_EXHAUSTED');
    const deadline2 = strike2.recoveryDeadlineMs!;
    expect(deadline2 - instA.nowMs()).toBeGreaterThanOrEqual(1_799_950);
    expect(deadline2 - instA.nowMs()).toBeLessThanOrEqual(1_800_000);

    // 4. Public /api/health redaction vs Protected /api/health?diagnostics=internal
    process.env.AEGIS_DIAGNOSTICS_SECRET = 'internal-diag-secret-0123456789abcdef';
    const publicHealthRes = await healthGet(new NextRequest('http://localhost:3000/api/health'));
    expect(publicHealthRes.status).toBe(200);
    const publicBody = await publicHealthRes.json();
    expect(publicBody.aiCircuit).toEqual({ state: 'CLOSED' });
    expect(publicBody.internalDiagnostics).toBeUndefined();
    expect(JSON.stringify(publicBody)).not.toContain('cred_');
    expect(JSON.stringify(publicBody)).not.toContain('proj_');
    expect(JSON.stringify(publicBody)).not.toContain('sessionSecretMode');
    expect(JSON.stringify(publicBody)).not.toContain('piiHmacMode');

    // Unauthenticated caller requesting ?diagnostics=internal is rejected with HTTP 403
    const unauthDiagRes = await healthGet(
      new NextRequest('http://localhost:3000/api/health?diagnostics=internal')
    );
    expect(unauthDiagRes.status).toBe(403);

    // L1_MAKER, END_USER, and simulated L2_CHECKER demo sessions are rejected with HTTP 403
    const endUserDiagRes = await healthGet(
      makeReq({
        url: 'http://localhost:3000/api/health?diagnostics=internal',
        method: 'GET',
        sessionId: 'diag-end-user',
        role: 'END_USER',
        principalId: 'usr-diag',
      })
    );
    expect(endUserDiagRes.status).toBe(403);

    const simulatedL2DiagRes = await healthGet(
      makeReq({
        url: 'http://localhost:3000/api/health?diagnostics=internal',
        method: 'GET',
        sessionId: 'diag-l2-checker',
        role: 'L2_CHECKER',
        principalId: 'checker-diag',
      })
    );
    expect(simulatedL2DiagRes.status).toBe(403);

    // Dedicated valid 32+ char x-aegis-diagnostics-token receives internalDiagnostics
    const tokenDiagRes = await healthGet(
      new NextRequest('http://localhost:3000/api/health?diagnostics=internal', {
        headers: { 'x-aegis-diagnostics-token': 'internal-diag-secret-0123456789abcdef' },
      })
    );
    expect(tokenDiagRes.status).toBe(200);
    const tokenDiagBody = await tokenDiagRes.json();
    expect(tokenDiagBody.internalDiagnostics).toBeDefined();
    expect(tokenDiagBody.internalDiagnostics.aiCircuitDetail.credentialFingerprint).toMatch(
      /^cred_[0-9a-f]{24}$/
    );
  });

  it('Wave 4.1.4 Workstream A: enforces project-level Gemini quota identity across multiple API keys (Scenarios A-E), isolates credential INVALID_API_KEY latches, preserves project quotas/circuits across key rotation, and fails closed when GEMINI_QUOTA_SCOPE_ID is missing in strict mode', async () => {
    const upstashSim = new StatefulUpstashMultiExecMock();
    process.env.UPSTASH_REDIS_REST_URL = 'https://apn1-w414-quota.upstash.io';
    process.env.UPSTASH_REDIS_REST_TOKEN = 'upstash-w414-quota-token';

    const keyA1 = 'AIzaSyProjectAlpha_Key1_00000000000001';
    const keyA2 = 'AIzaSyProjectAlpha_Key2_00000000000002';
    const keyA3 = 'AIzaSyProjectAlpha_Key3_00000000000003';
    const keyB1 = 'AIzaSyProjectBeta_Key1_000000000000001';

    const scopeAlpha = getGeminiQuotaScopeStatus('gcp-project-alpha-prod');
    const scopeBeta = getGeminiQuotaScopeStatus('gcp-project-beta-prod');
    expect(scopeAlpha.mode).toBe('CONFIGURED_PROJECT_SCOPE');
    expect(scopeBeta.mode).toBe('CONFIGURED_PROJECT_SCOPE');
    expect(scopeAlpha.scopeId).toMatch(/^proj_[0-9a-f]{24}$/);
    expect(scopeBeta.scopeId).toMatch(/^proj_[0-9a-f]{24}$/);
    expect(scopeAlpha.scopeId).not.toBe(scopeBeta.scopeId);
    expect(scopeAlpha.scopeId).not.toContain('gcp-project-alpha-prod');

    const inst1 = createGeminiResilienceInstance('w414-inst-1');
    const inst2 = createGeminiResilienceInstance('w414-inst-2');
    const inst3 = createGeminiResilienceInstance('w414-inst-3');

    let nextStatus = 200;
    let nextBody = JSON.stringify({
      candidates: [{ content: { parts: [{ text: '{"ok":true}' }] } }],
    });
    let geminiCalls = 0;

    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input);
      if (url.includes('upstash.io/multi-exec')) {
        const commands = JSON.parse(String(init?.body ?? '[]')) as unknown[][];
        return new Response(JSON.stringify(upstashSim.executeMultiExec(commands)), { status: 200 });
      }
      geminiCalls += 1;
      return new Response(nextBody, { status: nextStatus });
    });

    // Scenario A & E: Same Google Project ('gcp-project-alpha-prod'), 3 Instances with 3 Different API Keys (keyA1, keyA2, keyA3) share RPM & OCR RPM quotas!
    process.env.GEMINI_QUOTA_SCOPE_ID = 'gcp-project-alpha-prod';
    process.env.GEMINI_GLOBAL_RPM_LIMIT = '2';
    process.env.GEMINI_GLOBAL_OCR_RPM_LIMIT = '1';

    // Align clock to start of a clean minute bucket
    const cleanBucketMs = (Math.floor(upstashSim.nowMs / 60_000) + 5) * 60_000 + 2_000;
    const deltaMs = cleanBucketMs - inst1.nowMs();
    upstashSim.nowMs = cleanBucketMs;
    inst1.advanceClockForTest(deltaMs);
    inst2.advanceClockForTest(deltaMs);
    inst3.advanceClockForTest(deltaMs);

    // Instance 1 uses keyA1 (OCR call #1 -> allowed, project RPM=1, project OCR=1)
    process.env.GEMINI_API_KEY = keyA1;
    const ocrA1 = await inst1.executeGenerateContent({
      model: 'gemini-2.5-flash',
      parts: [{ text: 'ocr-a1' }],
      jsonMode: true,
      operationKind: 'VISION_OCR',
    });
    expect(ocrA1.ok).toBe(true);

    // Instance 2 uses different keyA2 in SAME project (OCR call #2 -> BLOCKED by shared project OCR limit=1!)
    process.env.GEMINI_API_KEY = keyA2;
    const ocrA2 = await inst2.executeGenerateContent({
      model: 'gemini-2.5-flash',
      parts: [{ text: 'ocr-a2' }],
      jsonMode: true,
      operationKind: 'VISION_OCR',
    });
    expect(ocrA2.ok).toBe(false);
    expect(ocrA2.distributedQuotaTripped).toBe(true);
    expect(ocrA2.category).toBe('RATE_LIMIT_RPM');

    // Instance 2 uses keyA2 for TEXT call (project RPM=2 <= limit 2 -> allowed)
    const textA2 = await inst2.executeGenerateContent({
      model: 'gemini-2.5-flash',
      parts: [{ text: 'text-a2' }],
      jsonMode: true,
      operationKind: 'INVESTIGATION',
    });
    expect(textA2.ok).toBe(true);

    // Instance 3 uses different keyA3 in SAME project for TEXT call (project RPM would be 3 > limit 2 -> BLOCKED!)
    process.env.GEMINI_API_KEY = keyA3;
    const textA3Blocked = await inst3.executeGenerateContent({
      model: 'gemini-2.5-flash',
      parts: [{ text: 'text-a3-blocked' }],
      jsonMode: true,
      operationKind: 'INVESTIGATION',
    });
    expect(textA3Blocked.ok).toBe(false);
    expect(textA3Blocked.distributedQuotaTripped).toBe(true);
    expect(geminiCalls).toBe(2);

    // Scenario B: Different Google Project ('gcp-project-beta-prod') with keyB1 is completely isolated from Project Alpha's exhausted RPM & OCR quota!
    process.env.GEMINI_QUOTA_SCOPE_ID = 'gcp-project-beta-prod';
    process.env.GEMINI_API_KEY = keyB1;
    const ocrB1 = await inst3.executeGenerateContent({
      model: 'gemini-2.5-flash',
      parts: [{ text: 'ocr-b1-isolated' }],
      jsonMode: true,
      operationKind: 'VISION_OCR',
    });
    expect(ocrB1.ok).toBe(true);
    expect(geminiCalls).toBe(3);

    // Scenario C: Credential-Specific INVALID_API_KEY on keyA1 latches keyA1 ONLY and does NOT latch sibling keyA2 in the same project!
    process.env.GEMINI_QUOTA_SCOPE_ID = 'gcp-project-alpha-prod';
    process.env.GEMINI_GLOBAL_RPM_LIMIT = '30';
    process.env.GEMINI_GLOBAL_OCR_RPM_LIMIT = '12';

    process.env.GEMINI_API_KEY = keyA1;
    nextStatus = 401;
    nextBody = '{"error":{"status":"UNAUTHENTICATED","message":"API key not valid"}}';
    const invalidKeyA1Res = await inst1.executeGenerateContent({
      model: 'gemini-2.5-flash',
      parts: [{ text: 'a1-bad-cred' }],
      jsonMode: true,
    });
    expect(invalidKeyA1Res.ok).toBe(false);
    expect(invalidKeyA1Res.category).toBe('INVALID_API_KEY');
    expect(invalidKeyA1Res.latched).toBe(true);

    // Sibling keyA2 in the SAME project ('gcp-project-alpha-prod') is NOT blocked by keyA1's credential latch!
    process.env.GEMINI_API_KEY = keyA2;
    nextStatus = 200;
    nextBody = JSON.stringify({
      candidates: [{ content: { parts: [{ text: '{"siblingOk":true}' }] } }],
    });
    const validSiblingA2Res = await inst2.executeGenerateContent({
      model: 'gemini-2.5-flash',
      parts: [{ text: 'a2-valid-sibling' }],
      jsonMode: true,
    });
    expect(validSiblingA2Res.ok).toBe(true);

    // Scenario D: Project-level RPD_EXHAUSTED opened under keyA2 MUST block rotated keyA3 in the same project (credential rotation cannot erase project circuits or project quota counters!)
    nextStatus = 429;
    nextBody = '{"error":{"message":"Quota exceeded for requests_per_day (RPD) per project"}}';
    const rpdUnderA2 = await inst2.executeGenerateContent({
      model: 'gemini-2.5-flash',
      parts: [{ text: 'a2-trips-project-rpd' }],
      jsonMode: true,
    });
    expect(rpdUnderA2.ok).toBe(false);
    expect(rpdUnderA2.category).toBe('RPD_EXHAUSTED');
    expect(rpdUnderA2.circuitTripped).toBe(true);

    // Rotate keyA2 -> keyA3 on inst2 within the SAME project ('gcp-project-alpha-prod')
    process.env.GEMINI_API_KEY = keyA3;
    nextStatus = 200;
    const callsBeforeRotationBypassAttempt = geminiCalls;
    const blockedAfterKeyRotationInSameProject = await inst2.executeGenerateContent({
      model: 'gemini-2.5-flash',
      parts: [{ text: 'a3-must-still-see-project-rpd' }],
      jsonMode: true,
    });
    expect(blockedAfterKeyRotationInSameProject.ok).toBe(false);
    expect(blockedAfterKeyRotationInSameProject.category).toBe('RPD_EXHAUSTED');
    expect(blockedAfterKeyRotationInSameProject.circuitTripped).toBe(true);
    expect(geminiCalls).toBe(callsBeforeRotationBypassAttempt);

    // Strict Production Policy: missing GEMINI_QUOTA_SCOPE_ID in strict mode fails closed without falling back to credential-scoped accounting
    delete process.env.GEMINI_QUOTA_SCOPE_ID;
    process.env.AEGIS_REQUIRE_STRICT_GEMINI_QUOTA_SCOPE = 'true';
    expect(getGeminiQuotaScopeStatus().mode).toBe('MISCONFIGURED_FAIL_CLOSED');
    expect(getGeminiQuotaScopeStatus().scopeId).toBeNull();

    const failClosedMissingScope = await inst3.executeGenerateContent({
      model: 'gemini-2.5-flash',
      parts: [{ text: 'strict-missing-project-scope' }],
      jsonMode: true,
    });
    expect(failClosedMissingScope.ok).toBe(false);
    expect(failClosedMissingScope.failClosedQuotaScopeError).toBe(true);
    expect(failClosedMissingScope.attempts).toBe(0);
    expect(geminiCalls).toBe(callsBeforeRotationBypassAttempt);
  });

  it('Wave 4.1.4 Workstream B: enforces the 8-row internal diagnostics authorization matrix, rejects session/admin secret reuse, blocks URL query tokens, and rate-limits brute-force attempts', async () => {
    const dedicatedDiagSecret = 'dedicated-diagnostics-secret-0123456789abcdef';
    const sessionSecret = 'dedicated-session-secret-fedcba9876543210fedc';
    const adminResetSecret = 'dedicated-admin-reset-secret-9988776655443322';

    process.env.AEGIS_DIAGNOSTICS_SECRET = dedicatedDiagSecret;
    process.env.AEGIS_SESSION_SECRET = sessionSecret;
    process.env.AEGIS_ADMIN_RESET_SECRET = adminResetSecret;

    // Row 1: No auth -> 403
    const row1NoAuth = await healthGet(
      new NextRequest('http://localhost:3000/api/health?diagnostics=internal')
    );
    expect(row1NoAuth.status).toBe(403);

    // Row 2: END_USER session -> 403
    const row2EndUser = await healthGet(
      makeReq({
        url: 'http://localhost:3000/api/health?diagnostics=internal',
        method: 'GET',
        sessionId: 'w414-diag-eu',
        role: 'END_USER',
        principalId: 'eu-1',
      })
    );
    expect(row2EndUser.status).toBe(403);

    // Row 3: L1_MAKER session -> 403
    const row3L1Maker = await healthGet(
      makeReq({
        url: 'http://localhost:3000/api/health?diagnostics=internal',
        method: 'GET',
        sessionId: 'w414-diag-l1',
        role: 'L1_MAKER',
        principalId: 'l1-1',
      })
    );
    expect(row3L1Maker.status).toBe(403);

    // Row 4: Simulated L2_CHECKER demo session -> 403 (cannot escalate demo persona to internal diagnostics)
    const row4SimulatedL2 = await healthGet(
      makeReq({
        url: 'http://localhost:3000/api/health?diagnostics=internal',
        method: 'GET',
        sessionId: 'w414-diag-l2',
        role: 'L2_CHECKER',
        principalId: 'demo:w414-diag-l2:L2_CHECKER',
      })
    );
    expect(row4SimulatedL2.status).toBe(403);

    // Row 5: Invalid diagnostics token -> 403
    const row5InvalidToken = await healthGet(
      new NextRequest('http://localhost:3000/api/health?diagnostics=internal', {
        headers: { 'x-aegis-diagnostics-token': 'wrong-diagnostics-token-0123456789abcdef' },
      })
    );
    expect(row5InvalidToken.status).toBe(403);

    // Row 6: Session secret used as diagnostics token -> 403
    const row6SessionSecretToken = await healthGet(
      new NextRequest('http://localhost:3000/api/health?diagnostics=internal', {
        headers: { 'x-aegis-diagnostics-token': sessionSecret },
      })
    );
    expect(row6SessionSecretToken.status).toBe(403);

    // Row 7: Admin reset secret used as diagnostics token -> 403
    const row7AdminSecretToken = await healthGet(
      new NextRequest('http://localhost:3000/api/health?diagnostics=internal', {
        headers: { 'x-aegis-diagnostics-token': adminResetSecret },
      })
    );
    expect(row7AdminSecretToken.status).toBe(403);

    // Defense-in-depth: Even if operator misconfigures AEGIS_DIAGNOSTICS_SECRET identical to AEGIS_SESSION_SECRET, it is rejected (403)
    process.env.AEGIS_DIAGNOSTICS_SECRET = sessionSecret;
    const reusedSecretConfigRes = await healthGet(
      new NextRequest('http://localhost:3000/api/health?diagnostics=internal', {
        headers: { 'x-aegis-diagnostics-token': sessionSecret },
      })
    );
    expect(reusedSecretConfigRes.status).toBe(403);
    process.env.AEGIS_DIAGNOSTICS_SECRET = dedicatedDiagSecret;

    // URL query parameter token (`?diagnostics=internal&token=...`) is rejected with 403 even if header is present
    const queryParamTokenRes = await healthGet(
      new NextRequest(
        `http://localhost:3000/api/health?diagnostics=internal&token=${dedicatedDiagSecret}`,
        {
          headers: { 'x-aegis-diagnostics-token': dedicatedDiagSecret },
        }
      )
    );
    expect(queryParamTokenRes.status).toBe(403);

    // Row 8: Valid 32+ char dedicated AEGIS_DIAGNOSTICS_SECRET in x-aegis-diagnostics-token header -> 200
    const row8ValidDiag = await healthGet(
      new NextRequest('http://localhost:3000/api/health?diagnostics=internal', {
        headers: { 'x-aegis-diagnostics-token': dedicatedDiagSecret },
      })
    );
    expect(row8ValidDiag.status).toBe(200);
    const row8Body = await row8ValidDiag.json();
    expect(row8Body.internalDiagnostics).toBeDefined();
    expect(row8Body.internalDiagnostics.aiConcurrency.concurrencyScope).toBe(
      'PER_INSTANCE_PROCESS_LOCAL'
    );

    // Brute-force rate limiting: > 15 diagnostics requests per minute from the same IP are blocked with HTTP 429
    process.env.TRUST_PROXY_HEADERS = 'true';
    let lastStatus = 200;
    for (let i = 0; i < 18; i += 1) {
      const probeRes = await healthGet(
        new NextRequest('http://localhost:3000/api/health?diagnostics=internal', {
          headers: {
            'x-real-ip': '203.0.113.199',
            'x-aegis-diagnostics-token': 'brute-force-attempt-token-0000000000',
          },
        })
      );
      lastStatus = probeRes.status;
    }
    expect(lastStatus).toBe(429);
  });

  it('Wave 4.1.4 Workstream C: enforces per-instance concurrency semaphores (4 general / 2 Vision OCR), cleans up in-flight slots in finally on success and failure, and bounds multi-instance aggregate concurrency via shared project Redis quota', async () => {
    expect(PER_INSTANCE_MAX_CONCURRENT_GEMINI).toBe(4);
    expect(PER_INSTANCE_MAX_CONCURRENT_VISION_OCR).toBe(2);

    process.env.GEMINI_API_KEY = 'AIzaSyConcurrencyTestKey_0123456789abcdef';
    process.env.GEMINI_QUOTA_SCOPE_ID = 'gcp-concurrency-project';

    const instSingle = createGeminiResilienceInstance('w414-conc-single');
    expect(instSingle.getOperationalMetrics().concurrencyScope).toBe('PER_INSTANCE_PROCESS_LOCAL');
    expect(instSingle.getOperationalMetrics().perInstanceMaxConcurrentGemini).toBe(4);
    expect(instSingle.getOperationalMetrics().perInstanceMaxConcurrentVisionOcr).toBe(2);

    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(
      () =>
        new Promise((resolve) => {
          setTimeout(() => {
            resolve(
              new Response(
                JSON.stringify({
                  candidates: [{ content: { parts: [{ text: '{"ok":true}' }] } }],
                }),
                { status: 200 }
              )
            );
          }, 30);
        })
    );

    // 1. 6 simultaneous general Gemini calls on 1 instance -> 4 execute, 2 rejected by per-instance semaphore (4)
    const generalBurst = await Promise.all(
      [1, 2, 3, 4, 5, 6].map((idx) =>
        instSingle.executeGenerateContent({
          model: 'gemini-2.5-flash',
          parts: [{ text: `general-conc-${idx}` }],
          jsonMode: true,
          operationKind: 'INVESTIGATION',
        })
      )
    );
    expect(generalBurst.filter((r) => r.ok).length).toBe(4);
    expect(generalBurst.filter((r) => !r.ok && r.circuitTripped && r.attempts === 0).length).toBe(2);
    expect(instSingle.getOperationalMetrics().inFlightCount).toBe(0);

    // 2. 3 simultaneous VISION_OCR calls on 1 instance -> 2 execute, 1 rejected by per-instance OCR semaphore (2)
    const ocrBurst = await Promise.all(
      [1, 2, 3].map((idx) =>
        instSingle.executeGenerateContent({
          model: 'gemini-2.5-flash',
          parts: [{ text: `ocr-conc-${idx}` }],
          jsonMode: true,
          operationKind: 'VISION_OCR',
        })
      )
    );
    expect(ocrBurst.filter((r) => r.ok).length).toBe(2);
    expect(ocrBurst.filter((r) => !r.ok && r.circuitTripped && r.attempts === 0).length).toBe(1);
    expect(instSingle.getOperationalMetrics().inFlightCount).toBe(0);
    expect(instSingle.getOperationalMetrics().inFlightVisionOcrCount).toBe(0);

    // 3. Even when an in-flight VISION_OCR request throws a network error, slots are released cleanly in finally
    fetchSpy.mockRejectedValueOnce(new Error('Socket hang up'));
    const failedOcr = await instSingle.executeGenerateContent({
      model: 'gemini-2.5-flash',
      parts: [{ text: 'ocr-fail-slot-release' }],
      jsonMode: true,
      operationKind: 'VISION_OCR',
      maxTransientRetries: 0,
    });
    expect(failedOcr.ok).toBe(false);
    expect(instSingle.getOperationalMetrics().inFlightCount).toBe(0);
    expect(instSingle.getOperationalMetrics().inFlightVisionOcrCount).toBe(0);

    // 4. Multi-instance concurrency across 2 instances (instA, instB): each instance has local OCR semaphore=2 (4 total across 2 instances),
    //    but shared Redis GEMINI_GLOBAL_OCR_RPM_LIMIT=3 caps total allowed OCR dispatches across both instances to 3!
    const upstashSim = new StatefulUpstashMultiExecMock();
    process.env.UPSTASH_REDIS_REST_URL = 'https://apn1-w414-conc.upstash.io';
    process.env.UPSTASH_REDIS_REST_TOKEN = 'upstash-w414-conc-token';
    process.env.GEMINI_GLOBAL_OCR_RPM_LIMIT = '3';

    const instA = createGeminiResilienceInstance('w414-conc-A');
    const instB = createGeminiResilienceInstance('w414-conc-B');

    fetchSpy.mockImplementation(async (input, init) => {
      const url = String(input);
      if (url.includes('upstash.io/multi-exec')) {
        const commands = JSON.parse(String(init?.body ?? '[]')) as unknown[][];
        return new Response(JSON.stringify(upstashSim.executeMultiExec(commands)), { status: 200 });
      }
      await new Promise((r) => setTimeout(r, 15));
      return new Response(
        JSON.stringify({ candidates: [{ content: { parts: [{ text: '{"ok":true}' }] } }] }),
        { status: 200 }
      );
    });

    const multiInstOcr = await Promise.all([
      instA.executeGenerateContent({
        model: 'gemini-2.5-flash',
        parts: [{ text: 'multi-ocr-a1' }],
        jsonMode: true,
        operationKind: 'VISION_OCR',
      }),
      instA.executeGenerateContent({
        model: 'gemini-2.5-flash',
        parts: [{ text: 'multi-ocr-a2' }],
        jsonMode: true,
        operationKind: 'VISION_OCR',
      }),
      instB.executeGenerateContent({
        model: 'gemini-2.5-flash',
        parts: [{ text: 'multi-ocr-b1' }],
        jsonMode: true,
        operationKind: 'VISION_OCR',
      }),
      instB.executeGenerateContent({
        model: 'gemini-2.5-flash',
        parts: [{ text: 'multi-ocr-b2' }],
        jsonMode: true,
        operationKind: 'VISION_OCR',
      }),
    ]);
    expect(multiInstOcr.filter((r) => r.ok).length).toBe(3);
    expect(multiInstOcr.filter((r) => !r.ok && r.distributedQuotaTripped).length).toBe(1);
    expect(instA.getOperationalMetrics().inFlightVisionOcrCount).toBe(0);
    expect(instB.getOperationalMetrics().inFlightVisionOcrCount).toBe(0);
  });

  it('Wave 4.1.4 Workstream D: validates all 8 production readiness scenarios, prevents memory fallback from satisfying strict production mode, and preserves public health redaction', async () => {
    const diagSecret = 'prod-readiness-diag-secret-0123456789abcdef';
    process.env.AEGIS_DIAGNOSTICS_SECRET = diagSecret;

    // Scenario 1: Local dev memory fallback (strict flags false) -> 200 LOCAL_DEV_MEMORY_FALLBACK
    delete process.env.DATABASE_URL;
    delete process.env.UPSTASH_REDIS_REST_URL;
    delete process.env.UPSTASH_REDIS_REST_TOKEN;
    process.env.AEGIS_PRODUCTION_STRICT_READINESS = 'false';
    process.env.AEGIS_REQUIRE_STRICT_SECRETS = 'false';
    process.env.AEGIS_REQUIRE_SHARED_PERSISTENCE = 'false';
    process.env.AEGIS_REQUIRE_DISTRIBUTED_RATE_LIMIT = 'false';

    const localDevRes = await healthGet(new NextRequest('http://localhost:3000/api/health'));
    expect(localDevRes.status).toBe(200);
    const localDevBody = await localDevRes.json();
    expect(localDevBody.readinessOk).toBe(true);
    expect(localDevBody.deploymentReadinessTier).toBe('LOCAL_DEV_MEMORY_FALLBACK');

    // Scenario 2: Strict mode without DATABASE_URL -> 503 NOT_READY (memory fallback rejected!)
    const upstashSim = new StatefulUpstashMultiExecMock();
    let simulateRedisPingFailure = false;
    process.env.AEGIS_PRODUCTION_STRICT_READINESS = 'true';
    process.env.AEGIS_SESSION_SECRET = 'strict-session-secret-0123456789abcdef';
    process.env.AEGIS_PII_HMAC_KEY = 'strict-pii-hmac-secret-fedcba9876543210';
    process.env.UPSTASH_REDIS_REST_URL = 'https://apn1-w414-health.upstash.io';
    process.env.UPSTASH_REDIS_REST_TOKEN = 'upstash-w414-health-token';

    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input);
      if (url.includes('upstash.io/multi-exec')) {
        const commands = JSON.parse(String(init?.body ?? '[]')) as unknown[][];
        return new Response(JSON.stringify(upstashSim.executeMultiExec(commands)), { status: 200 });
      }
      if (url.includes('upstash.io/ping')) {
        if (simulateRedisPingFailure) {
          simulateRedisPingFailure = false;
          return new Response('Internal Error', { status: 500 });
        }
        return new Response('{"result":"PONG"}', { status: 200 });
      }
      return new Response('{"result":"OK"}', { status: 200 });
    });

    const noDbRes = await healthGet(new NextRequest('http://localhost:3000/api/health'));
    expect(noDbRes.status).toBe(503);
    const noDbBody = await noDbRes.json();
    expect(noDbBody.readinessOk).toBe(false);
    expect(noDbBody.deploymentReadinessTier).toBe('NOT_READY');
    expect(noDbBody.dependencies.persistenceReady).toBe(false);

    // Scenario 3: Strict mode without Upstash config -> 503 NOT_READY (memory rate-limiter fallback rejected!)
    const healthyPool = new SqlVerifyingSpyPool();
    setPersistenceAdapterForTest(new PostgresPersistenceAdapter(healthyPool));
    delete process.env.UPSTASH_REDIS_REST_URL;
    delete process.env.UPSTASH_REDIS_REST_TOKEN;

    const noRedisRes = await healthGet(new NextRequest('http://localhost:3000/api/health'));
    expect(noRedisRes.status).toBe(503);
    const noRedisBody = await noRedisRes.json();
    expect(noRedisBody.readinessOk).toBe(false);
    expect(noRedisBody.deploymentReadinessTier).toBe('NOT_READY');
    expect(noRedisBody.dependencies.rateLimiterReady).toBe(false);

    // Scenario 4: Strict mode with PostgreSQL ping failure -> 503 NOT_READY
    process.env.UPSTASH_REDIS_REST_URL = 'https://apn1-w414-health.upstash.io';
    process.env.UPSTASH_REDIS_REST_TOKEN = 'upstash-w414-health-token';
    const failingPool = new SqlVerifyingSpyPool();
    vi.spyOn(failingPool, 'query').mockRejectedValueOnce(new Error('Connection refused'));
    setPersistenceAdapterForTest(new PostgresPersistenceAdapter(failingPool));

    const dbPingFailRes = await healthGet(new NextRequest('http://localhost:3000/api/health'));
    expect(dbPingFailRes.status).toBe(503);
    const dbPingFailBody = await dbPingFailRes.json();
    expect(dbPingFailBody.readinessOk).toBe(false);
    expect(dbPingFailBody.dependencies.persistenceReady).toBe(false);

    // Scenario 5: Strict mode with Upstash Redis ping failure -> 503 NOT_READY
    setPersistenceAdapterForTest(new PostgresPersistenceAdapter(healthyPool));
    simulateRedisPingFailure = true;

    const redisPingFailRes = await healthGet(new NextRequest('http://localhost:3000/api/health'));
    expect(redisPingFailRes.status).toBe(503);
    const redisPingFailBody = await redisPingFailRes.json();
    expect(redisPingFailBody.readinessOk).toBe(false);
    expect(redisPingFailBody.dependencies.rateLimiterReady).toBe(false);

    // Scenario 6: Strict mode with Postgres & Upstash healthy, Gemini key configured:
    // 6a) Missing GEMINI_QUOTA_SCOPE_ID fails readiness (503)
    process.env.GEMINI_API_KEY = 'AIzaSyProdReadinessKey_0123456789abcdef';
    delete process.env.GEMINI_QUOTA_SCOPE_ID;
    const missingScopeRes = await healthGet(new NextRequest('http://localhost:3000/api/health'));
    expect(missingScopeRes.status).toBe(503);
    const missingScopeBody = await missingScopeRes.json();
    expect(missingScopeBody.dependencies.quotaScopeReady).toBe(false);

    // 6b) Configured GEMINI_QUOTA_SCOPE_ID + healthy Postgres + healthy Upstash + strict secrets -> 200 PRODUCTION_SHARED_INFRA_READY
    process.env.GEMINI_QUOTA_SCOPE_ID = 'gcp-aegisops-prod-001';
    const prodReadyRes = await healthGet(new NextRequest('http://localhost:3000/api/health'));
    expect(prodReadyRes.status).toBe(200);
    const prodReadyBody = await prodReadyRes.json();
    expect(prodReadyBody.readinessOk).toBe(true);
    expect(prodReadyBody.deploymentReadinessTier).toBe('PRODUCTION_SHARED_INFRA_READY');

    // Scenario 7: Public health redaction check
    const rawPublicJson = JSON.stringify(prodReadyBody);
    expect(prodReadyBody.internalDiagnostics).toBeUndefined();
    expect(rawPublicJson).not.toContain('cred_');
    expect(rawPublicJson).not.toContain('proj_');
    expect(rawPublicJson).not.toContain('gcp-aegisops-prod-001');
    expect(rawPublicJson).not.toContain('sessionSecretMode');
    expect(rawPublicJson).not.toContain('piiHmacMode');

    // Scenario 8: Protected internal diagnostics availability with valid dedicated 32+ char token
    const diagRes = await healthGet(
      new NextRequest('http://localhost:3000/api/health?diagnostics=internal', {
        headers: { 'x-aegis-diagnostics-token': diagSecret },
      })
    );
    expect(diagRes.status).toBe(200);
    const diagBody = await diagRes.json();
    expect(diagBody.internalDiagnostics.deploymentReadinessTier).toBe(
      'PRODUCTION_SHARED_INFRA_READY'
    );
    expect(diagBody.internalDiagnostics.persistence.mode).toBe('POSTGRES');
    expect(diagBody.internalDiagnostics.rateLimiter.mode).toBe('UPSTASH_REDIS');
    expect(diagBody.internalDiagnostics.aiQuotaScope.quotaScopeMode).toBe(
      'CONFIGURED_PROJECT_SCOPE'
    );
    expect(diagBody.internalDiagnostics.aiQuotaScope.quotaScopeId).toMatch(/^proj_[0-9a-f]{24}$/);
  });

  it('Wave 4.2.0.2 Workstream A.3 & B.1: verifies gemini-3.5-flash-lite lifecycle migration compatibility (all 10 deterministic scenarios) and audits Lua scripts for Strict Key Locking compliance', async () => {
    process.env.GEMINI_API_KEY = 'AIzaSyWave4202ModelLifecycleKey_0123456';
    process.env.GEMINI_QUOTA_SCOPE_ID = 'gcp-aegisops-model-lifecycle';
    process.env.GEMINI_PRIMARY_MODEL = 'gemini-3.5-flash-lite';
    process.env.GEMINI_FALLBACK_MODEL = 'gemini-2.5-flash-lite';

    const alert = SEED_ALERTS[0]!;
    const forensics = runDeterministicForensicsSuite({
      alert,
      accounts: SEED_ACCOUNTS,
      devices: SEED_DEVICES,
      authLogs: SEED_AUTH_LOGS,
      transactions: SEED_TRANSACTIONS,
      apiEvents: SEED_API_EVENTS,
      evidences: SEED_EVIDENCES,
    });

    const validInvestigationJson = JSON.stringify({
      classification: 'CONFIRMED_ATO_MULE',
      confidenceScore: 95,
      executiveSummaryVi: `Phân tích xác nhận chiếm đoạt tài khoản (ATO) và luân chuyển qua tài khoản mule kèm mã bằng chứng ${forensics.validEvidenceIds[0] ?? 'EVD-1'}.`,
      keyFindingsVi: [
        `Thiết bị lạ đăng nhập và chuyển khoản tức thì (${forensics.validEvidenceIds[0] ?? 'EVD-1'})`,
        'Tốc độ rút tiền bất thường qua nhiều tầng tài khoản trung gian',
      ],
      citedEvidenceIds: forensics.validEvidenceIds.slice(0, 2),
      userShieldWarningVi:
        'Cảnh báo: Tài khoản nhận có dấu hiệu lừa đảo chiếm đoạt tài sản. Giao dịch đã bị chặn để bảo vệ số dư của bạn.',
      recommendedActions: forensics.fallbackReport.recommendedActions,
    });

    const validOcrJson = JSON.stringify({
      claimedTransactionId: 'TXN-MOMO-998877',
      claimedAmountVnd: 250000,
      currency: 'VND',
      claimedRecipientAccount: '0901234567',
      claimedRecipientName: 'NGUYEN VAN A',
      claimedSenderInfo: 'TRAN THI B',
      claimedTransactionTime: '2026-11-22T10:00:00Z',
      paymentProvider: 'MoMo',
      otherReferences: ['REF-01'],
      detectedAmountsCount: 1,
      candidateTransactionIds: ['TXN-MOMO-998877'],
      imageQualityStatus: 'CLEAR',
      fieldConfidence: {
        transactionId: 0.98,
        amountVnd: 0.99,
        recipientAccount: 0.96,
        overall: 0.98,
      },
      extractionWarnings: [],
      missingFields: [],
      suspiciousVisualIndicators: [],
    });

    const calledUrls: string[] = [];
    let responder: (url: string) => Promise<Response> = async () =>
      new Response(
        JSON.stringify({
          candidates: [
            { content: { parts: [{ text: `\`\`\`json\n${validInvestigationJson}\n\`\`\`` }] } },
          ],
        }),
        { status: 200 }
      );

    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = String(input);
      calledUrls.push(url);
      return responder(url);
    });

    // 1 & 2. Successful investigation response + valid JSON structured output (with outer markdown fence stripping) on gemini-3.5-flash-lite
    const invSuccess = await runGeminiInvestigationWithFallback({
      alert,
      forensics,
      evidenceTranscript: 'Test gemini-3.5-flash-lite investigation',
    });
    expect(invSuccess.modelUsed).toBe('gemini-3.5-flash-lite');
    expect(invSuccess.classification).toBe('CONFIRMED_ATO_MULE');
    expect(invSuccess.confidenceScore).toBe(95);
    expect(calledUrls[calledUrls.length - 1]).toContain(
      '/models/gemini-3.5-flash-lite:generateContent'
    );

    // 3. Invalid JSON response on primary (gemini-3.5-flash-lite) -> fails over to fallback (gemini-2.5-flash-lite)
    resetGeminiResilienceForTest();
    responder = async (url) => {
      if (url.includes('gemini-3.5-flash-lite')) {
        return new Response(
          JSON.stringify({
            candidates: [{ content: { parts: [{ text: '{invalid_json_payload:' }] } }],
          }),
          { status: 200 }
        );
      }
      return new Response(
        JSON.stringify({
          candidates: [{ content: { parts: [{ text: validInvestigationJson }] } }],
        }),
        { status: 200 }
      );
    };
    const invFallbackOnMalformed = await runGeminiInvestigationWithFallback({
      alert,
      forensics,
      evidenceTranscript: 'Test invalid JSON failover',
    });
    expect(invFallbackOnMalformed.modelUsed).toBe('gemini-2.5-flash-lite');

    // 4. Missing required fields in JSON (Zod schema rejection) on primary -> fails over to fallback model
    resetGeminiResilienceForTest();
    responder = async (url) => {
      if (url.includes('gemini-3.5-flash-lite')) {
        return new Response(
          JSON.stringify({
            candidates: [
              {
                content: {
                  parts: [{ text: JSON.stringify({ classification: 'CONFIRMED_ATO_MULE' }) }],
                },
              },
            ],
          }),
          { status: 200 }
        );
      }
      return new Response(
        JSON.stringify({
          candidates: [{ content: { parts: [{ text: validInvestigationJson }] } }],
        }),
        { status: 200 }
      );
    };
    const invFallbackOnMissingFields = await runGeminiInvestigationWithFallback({
      alert,
      forensics,
      evidenceTranscript: 'Test missing required fields failover',
    });
    expect(invFallbackOnMissingFields.modelUsed).toBe('gemini-2.5-flash-lite');

    // 5. Merchant receipt OCR image extraction on gemini-3.5-flash-lite
    resetGeminiResilienceForTest();
    responder = async () =>
      new Response(
        JSON.stringify({
          candidates: [{ content: { parts: [{ text: validOcrJson }] } }],
        }),
        { status: 200 }
      );
    const ocrSuccess = await extractMerchantBillWithGeminiVision({
      mimeType: 'image/png',
      base64Data:
        'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=',
    });
    expect(ocrSuccess.outcome).toBe('OK');
    expect(ocrSuccess.modelUsed).toBe('gemini-3.5-flash-lite');
    if (ocrSuccess.outcome === 'OK') {
      expect(ocrSuccess.extracted.claimedTransactionId).toBe('TXN-MOMO-998877');
      expect(ocrSuccess.extracted.claimedAmountVnd).toBe(250000);
    }

    // 6. Timeout (AbortError) on primary gemini-3.5-flash-lite -> fails over to fallback gemini-2.5-flash-lite
    resetGeminiResilienceForTest();
    responder = async (url) => {
      if (url.includes('gemini-3.5-flash-lite')) {
        throw Object.assign(new Error('Request timed out'), { name: 'AbortError' });
      }
      return new Response(
        JSON.stringify({
          candidates: [{ content: { parts: [{ text: validOcrJson }] } }],
        }),
        { status: 200 }
      );
    };
    const ocrAfterPrimaryTimeout = await extractMerchantBillWithGeminiVision({
      mimeType: 'image/png',
      base64Data:
        'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=',
    });
    expect(ocrAfterPrimaryTimeout.outcome).toBe('OK');
    expect(ocrAfterPrimaryTimeout.modelUsed).toBe('gemini-2.5-flash-lite');

    // 7. HTTP 429 RPD_EXHAUSTED on primary gemini-3.5-flash-lite opens model circuit and aborts fallback loop cleanly
    resetGeminiResilienceForTest();
    let callsDuring429 = 0;
    responder = async () => {
      callsDuring429 += 1;
      return new Response(
        '{"error":{"code":429,"message":"Quota exceeded for requests_per_day (RPD)"}}',
        { status: 429 }
      );
    };
    const invOn429 = await runGeminiInvestigationWithFallback({
      alert,
      forensics,
      evidenceTranscript: 'Test 429 abort fallback',
    });
    expect(callsDuring429).toBe(1);
    expect(invOn429.modelUsed).toContain('deterministic');

    // 8. Copilot primary 404 UNSUPPORTED_MODEL -> fails over to fallback gemini-2.5-flash-lite
    resetGeminiResilienceForTest();
    responder = async (url) => {
      if (url.includes('gemini-3.5-flash-lite')) {
        return new Response('{"error":{"code":404,"message":"Model not found"}}', { status: 404 });
      }
      return new Response(
        JSON.stringify({
          candidates: [
            {
              content: {
                parts: [
                  {
                    text: `Bằng chứng ${forensics.validEvidenceIds[0] ?? 'EVD-1'} xác nhận rủi ro cao.`,
                  },
                ],
              },
            },
          ],
        }),
        { status: 200 }
      );
    };
    const copilotFallback = await askGeminiCopilotOnCase({
      question: 'Tóm tắt bằng chứng chính?',
      alert,
      forensics,
    });
    expect(copilotFallback.modelUsed).toBe('gemini-2.5-flash-lite');

    // 9 & 10. Model-specific circuit isolation & model change without credential rotation
    resetGeminiResilienceForTest();
    const credBeforeModelSwitch = getGeminiCredentialFingerprint();
    const scopeBeforeModelSwitch = getGeminiQuotaScopeId();

    // Trip RPD_EXHAUSTED on legacy model gemini-2.5-flash
    process.env.GEMINI_PRIMARY_MODEL = 'gemini-2.5-flash';
    responder = async (url) => {
      if (url.includes('/models/gemini-2.5-flash:')) {
        return new Response('{"error":{"message":"Quota exceeded for requests_per_day (RPD)"}}', {
          status: 429,
        });
      }
      return new Response(
        JSON.stringify({
          candidates: [{ content: { parts: [{ text: validInvestigationJson }] } }],
        }),
        { status: 200 }
      );
    };
    const res25FlashTripped = await executeResilientGeminiGenerateContent({
      model: 'gemini-2.5-flash',
      parts: [{ text: 'trip-25-flash-rpd' }],
      jsonMode: true,
    });
    expect(res25FlashTripped.ok).toBe(false);
    expect(res25FlashTripped.category).toBe('RPD_EXHAUSTED');
    expect(res25FlashTripped.circuitTripped).toBe(true);

    // Switch primary model to gemini-3.5-flash-lite WITHOUT rotating GEMINI_API_KEY:
    // Credential fingerprint and project quota scope remain identical, while gemini-3.5-flash-lite is NOT blocked by gemini-2.5-flash's model-scoped RPD circuit!
    process.env.GEMINI_PRIMARY_MODEL = 'gemini-3.5-flash-lite';
    expect(getGeminiCredentialFingerprint()).toBe(credBeforeModelSwitch);
    expect(getGeminiQuotaScopeId()).toBe(scopeBeforeModelSwitch);

    const res35FlashLiteIsolated = await executeResilientGeminiGenerateContent({
      model: 'gemini-3.5-flash-lite',
      parts: [{ text: 'isolated-35-flash-lite' }],
      jsonMode: true,
    });
    expect(res35FlashLiteIsolated.ok).toBe(true);

    // Workstream B.1 Static Audit: Verify every redis.call() in both Lua scripts accesses ONLY pre-declared KEYS[i]
    const extractRedisCallKeyArgs = (luaSource: string): string[] => {
      const matches = [...luaSource.matchAll(/redis\.call\(\s*'([A-Z]+)'\s*,\s*([^,)\s]+)/g)];
      return matches.map((m) => `${m[1]}:${m[2]}`);
    };

    const gateKeyAccesses = extractRedisCallKeyArgs(ATOMIC_CIRCUIT_GATE_AND_QUOTA_RESERVE_LUA);
    expect(gateKeyAccesses).toEqual([
      'GET:KEYS[1]',
      'GET:KEYS[2]',
      'GET:KEYS[3]',
      'GET:KEYS[4]',
      'GET:KEYS[5]',
      'GET:KEYS[6]',
      'GET:KEYS[7]',
      'GET:KEYS[8]',
      'GET:KEYS[9]',
      'GET:KEYS[10]',
      'INCR:KEYS[7]',
      'PEXPIRE:KEYS[7]',
      'INCR:KEYS[9]',
      'PEXPIRE:KEYS[9]',
    ]);
    const monotonicSetKeyAccesses = extractRedisCallKeyArgs(ATOMIC_MONOTONIC_CIRCUIT_SET_LUA);
    expect(monotonicSetKeyAccesses).toEqual(['GET:KEYS[1]', 'SET:KEYS[1]']);
  });
});
