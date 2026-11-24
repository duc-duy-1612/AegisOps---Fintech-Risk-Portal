import { afterEach, describe, expect, it, vi } from 'vitest';
import { NextRequest } from 'next/server';
import { POST as copilotPost } from '@/app/api/copilot/route';
import { GET as healthGet } from '@/app/api/health/route';
import {
  GET as cleanupGet,
  POST as cleanupPost,
} from '@/app/api/internal/cleanup/route';
import { POST as investigatePost } from '@/app/api/investigate/route';
import { POST as merchantVisionPost } from '@/app/api/merchant/vision/route';
import { POST as sandboxPost } from '@/app/api/sandbox/route';
import { synthesizeSandboxCase } from '@/domain/sandbox-synthesizer';
import { extractSandboxEntitiesWithGeminiVision } from '@/infrastructure/gemini-agent';
import {
  createGeminiResilienceInstance,
  evaluateGeminiFallbackReadiness,
  parseStrictPositiveIntEnv,
  resetGeminiResilienceForTest,
  resolveGlobalGeminiQuotaConfig,
} from '@/infrastructure/gemini-resilience';
import {
  InMemoryPersistenceAdapter,
  PostgresPersistenceAdapter,
  runBoundedExpiredSessionDrain,
  setPersistenceAdapterForTest,
  type PgQueryableClient,
  type PgQueryablePool,
} from '@/infrastructure/persistence-adapter';
import { SEED_ACCOUNTS } from '@/infrastructure/seed-scenarios';
import {
  SESSION_COOKIE_NAME,
  createSignedSessionToken,
} from '@/infrastructure/session-auth';
import { createEmptyDelta } from '@/infrastructure/workspace-store';
import {
  createWorkspaceAsyncCoordinator,
  filterMatchingSessionDelta,
  isConfirmedSessionInvalidationResponse,
} from '@/presentation/hooks/workspace-lifecycle';

const VALID_32X32_PNG_BASE64 = Buffer.from([
  0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
  0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
  0x00, 0x00, 0x00, 0x20,
  0x00, 0x00, 0x00, 0x20,
  0x08, 0x02, 0x00, 0x00, 0x00,
  0xfc, 0x18, 0xed, 0xa3,
  0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
]).toString('base64');

const VALID_32X32_PNG_DATA_URL = `data:image/png;base64,${VALID_32X32_PNG_BASE64}`;

const ORIGINAL_ENV = { ...process.env };

const restoreEnv = () => {
  for (const key of Object.keys(process.env)) {
    if (!(key in ORIGINAL_ENV)) {
      delete process.env[key];
    }
  }
  for (const [key, val] of Object.entries(ORIGINAL_ENV)) {
    if (val === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = val;
    }
  }
};

const makeSignedRequest = (params: {
  path: string;
  body: Record<string, unknown>;
  sessionId: string;
  clientIp: string;
  extraHeaders?: Record<string, string>;
}): NextRequest => {
  const token = createSignedSessionToken({
    sessionId: params.sessionId,
    principalId: `principal-${params.sessionId}`,
    role: 'L2_CHECKER',
  });
  return new NextRequest(`http://localhost:3000${params.path}`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      origin: 'http://localhost:3000',
      'x-real-ip': params.clientIp,
      cookie: `${SESSION_COOKIE_NAME}=${token}`,
      ...(params.extraHeaders ?? {}),
    },
    body: JSON.stringify(params.body),
  });
};

class RetentionSpyPool implements PgQueryablePool {
  public readonly queries: Array<{ sql: string; values: unknown[] }> = [];
  public readonly rows = new Map<
    string,
    {
      session_id: string;
      status: string;
      delta_json: Record<string, unknown>;
      delta_integrity_tag: string;
      expires_at: string;
      revoked_at: string | null;
    }
  >();

  async query(text: string, values: unknown[] = []) {
    const normalized = text.replace(/\s+/g, ' ').trim();
    this.queries.push({ sql: normalized, values });

    if (normalized.includes('SELECT 1 AS ok')) {
      return { rows: [{ ok: 1 }], rowCount: 1 };
    }

    if (
      normalized.includes('UPDATE aegis_workspace_sessions') &&
      normalized.includes("status = 'REVOKED'")
    ) {
      const sid = String(values[0]);
      const existing = this.rows.get(sid);
      if (existing) {
        this.rows.set(sid, {
          ...existing,
          status: 'REVOKED',
          delta_json: {
            sessionId: sid,
            redactedOnRevocation: true,
          },
          delta_integrity_tag: '',
          revoked_at: existing.revoked_at ?? new Date().toISOString(),
        });
      }
      return { rows: [], rowCount: existing ? 1 : 0 };
    }

    if (
      normalized.includes('DELETE FROM aegis_workspace_sessions') &&
      normalized.includes('FOR UPDATE SKIP LOCKED')
    ) {
      const cutoffMs = Date.parse(String(values[0]));
      const limit = Number(values[1] ?? 100);
      const expired = Array.from(this.rows.values())
        .filter((r) => Date.parse(r.expires_at) <= cutoffMs)
        .sort((a, b) => Date.parse(a.expires_at) - Date.parse(b.expires_at))
        .slice(0, limit);
      for (const row of expired) {
        this.rows.delete(row.session_id);
      }
      return {
        rows: expired.map((r) => ({ session_id: r.session_id })),
        rowCount: expired.length,
      };
    }

    return { rows: [], rowCount: 0 };
  }

  async connect(): Promise<PgQueryableClient> {
    return {
      query: (text: string, values?: unknown[]) => this.query(text, values),
      release: () => undefined,
    };
  }
}

class SharedUpstashLuaMock {
  public readonly counters = new Map<string, number>();
  public readonly seenRpmLimits: string[] = [];

  public handle(url: string, init?: RequestInit): Response {
    if (url.endsWith('/ping')) {
      return new Response(JSON.stringify({ result: 'PONG' }), { status: 200 });
    }
    const bodyText = typeof init?.body === 'string' ? init.body : '';
    const commands = JSON.parse(bodyText) as unknown[][];
    const results = commands.map((cmd) => {
      const op = String(cmd[0] ?? '').toUpperCase();
      if (op === 'EVAL') {
        const numKeys = Number(cmd[2] ?? 0);
        const keys = cmd.slice(3, 3 + numKeys).map(String);
        const argv = cmd.slice(3 + numKeys);
        const rpmKey = keys[6] ?? 'rpm';
        const ocrKey = keys[8] ?? 'ocr';
        const rpmMaxRaw = String(argv[1] ?? '');
        const ocrMaxRaw = String(argv[2] ?? '');
        this.seenRpmLimits.push(rpmMaxRaw);
        const rpmMax = Number(rpmMaxRaw);
        const ocrMax = Number(ocrMaxRaw);
        const isOcr = String(argv[3] ?? '0') === '1';

        if (!Number.isFinite(rpmMax) || !Number.isFinite(ocrMax)) {
          return { error: 'ERR user_script: attempt to compare nil with number' };
        }

        const currRpm = this.counters.get(rpmKey) ?? 0;
        const nextRpm = currRpm + 1;
        if (nextRpm > rpmMax) {
          return { result: ['QUOTA_RPM_EXCEEDED', String(currRpm), String(nextRpm)] };
        }
        if (isOcr) {
          const currOcr = this.counters.get(ocrKey) ?? 0;
          const nextOcr = currOcr + 1;
          if (nextOcr > ocrMax) {
            return { result: ['QUOTA_OCR_EXCEEDED', String(currOcr), String(nextOcr)] };
          }
          this.counters.set(ocrKey, nextOcr);
        }
        this.counters.set(rpmKey, nextRpm);
        return { result: ['ALLOWED', String(nextRpm), '0'] };
      }
      if (op === 'INCR') {
        const key = String(cmd[1] ?? '');
        const next = (this.counters.get(key) ?? 0) + 1;
        this.counters.set(key, next);
        return { result: next };
      }
      if (op === 'PEXPIRE') {
        return { result: 1 };
      }
      return { result: 'OK' };
    });

    return new Response(JSON.stringify(results), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}

afterEach(() => {
  vi.restoreAllMocks();
  setPersistenceAdapterForTest(null);
  restoreEnv();
  resetGeminiResilienceForTest();
});

describe('Wave B1.0.3.1 — Phase 1: Data Retention, Revocation & Scheduled Cleanup (B103R-DATA-01)', () => {
  it('scrubs delta_json on Postgres revokeSession and physically deletes expired sessions in bounded SKIP LOCKED batches without touching active sessions', async () => {
    const spyPool = new RetentionSpyPool();
    const adapter = new PostgresPersistenceAdapter(spyPool);

    const nowMs = Date.now();
    spyPool.rows.set('sess-active-1', {
      session_id: 'sess-active-1',
      status: 'ACTIVE',
      delta_json: { customEvidences: [{ imageDataUrl: 'data:image/png;base64,ACTIVE' }] },
      delta_integrity_tag: 'tag-active',
      expires_at: new Date(nowMs + 3600_000).toISOString(),
      revoked_at: null,
    });
    spyPool.rows.set('sess-expired-1', {
      session_id: 'sess-expired-1',
      status: 'ACTIVE',
      delta_json: { customEvidences: [{ imageDataUrl: 'data:image/png;base64,EXP1' }] },
      delta_integrity_tag: 'tag-exp1',
      expires_at: new Date(nowMs - 7200_000).toISOString(),
      revoked_at: null,
    });
    spyPool.rows.set('sess-expired-2', {
      session_id: 'sess-expired-2',
      status: 'ACTIVE',
      delta_json: { customEvidences: [{ imageDataUrl: 'data:image/png;base64,EXP2' }] },
      delta_integrity_tag: 'tag-exp2',
      expires_at: new Date(nowMs - 3600_000).toISOString(),
      revoked_at: null,
    });

    // 1. Revoke active session -> scrubs delta_json & delta_integrity_tag while preserving tombstone row
    await adapter.revokeSession('sess-active-1');
    const revokedRow = spyPool.rows.get('sess-active-1');
    expect(revokedRow?.status).toBe('REVOKED');
    expect(revokedRow?.delta_integrity_tag).toBe('');
    expect(JSON.stringify(revokedRow?.delta_json)).not.toContain('data:image/png');
    expect(revokedRow?.delta_json.redactedOnRevocation).toBe(true);
    // Repeated revocation is idempotent
    await adapter.revokeSession('sess-active-1');
    expect(spyPool.rows.get('sess-active-1')?.status).toBe('REVOKED');

    // 2. Bounded batch purge (batchSize = 1) deletes oldest expired row only
    const pass1 = await adapter.purgeExpiredSessions({ batchSize: 1 });
    expect(pass1.purgedCount).toBe(1);
    expect(pass1.batchLimit).toBe(1);
    expect(spyPool.rows.has('sess-expired-1')).toBe(false);
    expect(spyPool.rows.has('sess-expired-2')).toBe(true);
    expect(spyPool.rows.has('sess-active-1')).toBe(true);

    // 3. Second pass deletes remaining expired row; third pass is idempotent (0)
    const pass2 = await adapter.purgeExpiredSessions({ batchSize: 10 });
    expect(pass2.purgedCount).toBe(1);
    expect(spyPool.rows.has('sess-expired-2')).toBe(false);
    expect(spyPool.rows.has('sess-active-1')).toBe(true);

    const pass3 = await adapter.purgeExpiredSessions({ batchSize: 10 });
    expect(pass3.purgedCount).toBe(0);
    expect(
      spyPool.queries.some(
        (q) =>
          q.sql.includes('DELETE FROM aegis_workspace_sessions') &&
          q.sql.includes('FOR UPDATE SKIP LOCKED')
      )
    ).toBe(true);
  });

  it('protects /api/internal/cleanup with dedicated high-entropy CRON_SECRET and rejects reused or missing credentials', async () => {
    const memAdapter = new InMemoryPersistenceAdapter();
    setPersistenceAdapterForTest(memAdapter);

    const expiredDelta = {
      ...createEmptyDelta('sess-mem-expired'),
      stateRevision: 1,
      customEvidences: [
        {
          id: 'EVD-1',
          alertId: 'ALT-1',
          kind: 'SCREENSHOT_IMAGE' as const,
          title: 'Sample',
          textContent: 'Synthetic',
          imageDataUrl: VALID_32X32_PNG_DATA_URL,
          extractedSignals: [],
        },
      ],
    };
    await memAdapter.commitSession({
      sessionId: 'sess-mem-expired',
      principalId: 'p1',
      expectedRevision: 0,
      nextDelta: expiredDelta,
      expiresAtIso: new Date(Date.now() - 60_000).toISOString(),
    });
    await memAdapter.commitSession({
      sessionId: 'sess-mem-active',
      principalId: 'p2',
      expectedRevision: 0,
      nextDelta: { ...createEmptyDelta('sess-mem-active'), stateRevision: 1 },
      expiresAtIso: new Date(Date.now() + 600_000).toISOString(),
    });

    // Missing CRON_SECRET -> 401
    delete process.env.CRON_SECRET;
    const unconfRes = await cleanupGet(
      new NextRequest('http://localhost:3000/api/internal/cleanup', {
        headers: { authorization: 'Bearer anything' },
      })
    );
    expect(unconfRes.status).toBe(401);

    // Reused AEGIS_SESSION_SECRET as CRON_SECRET -> 401 (enforces secret separation)
    const sharedSecret = 'a'.repeat(40);
    process.env.AEGIS_SESSION_SECRET = sharedSecret;
    process.env.CRON_SECRET = sharedSecret;
    const reusedRes = await cleanupGet(
      new NextRequest('http://localhost:3000/api/internal/cleanup', {
        headers: { authorization: `Bearer ${sharedSecret}` },
      })
    );
    expect(reusedRes.status).toBe(401);

    // Dedicated CRON_SECRET with wrong token -> 401
    const dedicatedCronSecret = 'c'.repeat(48);
    process.env.CRON_SECRET = dedicatedCronSecret;
    const wrongRes = await cleanupPost(
      new NextRequest('http://localhost:3000/api/internal/cleanup', {
        method: 'POST',
        headers: { authorization: `Bearer ${'d'.repeat(48)}` },
      })
    );
    expect(wrongRes.status).toBe(401);

    // Valid dedicated CRON_SECRET -> 200 and purges only expired session
    const okRes = await cleanupGet(
      new NextRequest('http://localhost:3000/api/internal/cleanup', {
        headers: { authorization: `Bearer ${dedicatedCronSecret}` },
      })
    );
    expect(okRes.status).toBe(200);
    const okJson = await okRes.json();
    expect(okJson.ok).toBe(true);
    expect(okJson.purgedCount).toBe(1);
    expect(await memAdapter.loadSession('sess-mem-expired')).toBeNull();
    expect(await memAdapter.loadSession('sess-mem-active')).not.toBeNull();
  });

  it('distinguishes confirmed session expiration from transient errors and strips mismatched cross-session deltas', () => {
    expect(isConfirmedSessionInvalidationResponse(401, 'SESSION_REVOKED')).toBe(true);
    expect(isConfirmedSessionInvalidationResponse(403, 'SESSION_OWNERSHIP_REQUIRED')).toBe(true);
    expect(isConfirmedSessionInvalidationResponse(403, 'PREDICTABLE_DEFAULT_SESSION_FORBIDDEN')).toBe(true);
    expect(isConfirmedSessionInvalidationResponse(401, undefined)).toBe(true);

    // Must NOT wipe localStorage on transient / unrelated failures
    expect(isConfirmedSessionInvalidationResponse(503, 'PERSISTENCE_UNAVAILABLE')).toBe(false);
    expect(isConfirmedSessionInvalidationResponse(500, 'INTERNAL_ERROR')).toBe(false);
    expect(isConfirmedSessionInvalidationResponse(429, 'RATE_LIMITED')).toBe(false);
    expect(isConfirmedSessionInvalidationResponse(403, 'DEMO_PERSONA_SWITCH_DISABLED')).toBe(false);
    expect(isConfirmedSessionInvalidationResponse(403, 'CSRF_ORIGIN_MISMATCH')).toBe(false);

    // Cross-session delta filter prevents 403 CROSS_SESSION_ACCESS_DENIED loops
    const staleDelta = { sessionId: 'sess-old-expired', stateRevision: 4 };
    expect(filterMatchingSessionDelta(staleDelta, 'sess-new-fresh')).toBeNull();
    expect(filterMatchingSessionDelta(staleDelta, 'sess-old-expired')).toEqual(staleDelta);
  });
});

describe('Wave B1.0.3.1 — Phase 2: Truthful Sandbox & Copilot AI Provenance (B103R-SANDBOX-01)', () => {
  it('propagates PRIMARY_MODEL, FALLBACK_MODEL, DETERMINISTIC_FALLBACK, and AI_UNAVAILABLE accurately to Sandbox evidence titles without secret leakage', async () => {
    process.env.GEMINI_API_KEY = 'AIzaSySandboxSecretNeverLeak999999';
    process.env.GEMINI_PRIMARY_MODEL = 'gemini-3.5-flash-lite';
    process.env.GEMINI_FALLBACK_MODEL = 'gemini-3.1-flash-lite';
    process.env.AEGIS_E2E_DISABLE_EXTERNAL_AI = 'false';

    // 1. Primary Gemini Vision succeeds
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          candidates: [
            {
              content: {
                parts: [
                  {
                    text: JSON.stringify({
                      ocrExtractedTextVi: 'Nội dung bill mô phỏng 15.000.000 VNĐ',
                      recipientAccountNumber: '1903888999111',
                      recipientOwnerName: 'NGUYEN VAN TEST',
                      amountVnd: 15000000,
                      scamArchetypeVi: 'Giả danh Công an mô phỏng',
                      extractedSignals: ['Kịch bản ép chuyển khoản'],
                    }),
                  },
                ],
              },
            },
          ],
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } }
      )
    );
    const primaryRes = await extractSandboxEntitiesWithGeminiVision('', VALID_32X32_PNG_DATA_URL);
    expect(primaryRes.aiMetadata?.executionPath).toBe('PRIMARY_MODEL');
    const primaryBundle = synthesizeSandboxCase({
      rawTranscript: '',
      imageDataUrl: VALID_32X32_PNG_DATA_URL,
      extractedOverrides: primaryRes,
      existingAccounts: SEED_ACCOUNTS,
    });
    expect(primaryBundle.evidence.title).toBe('Ảnh bằng chứng tải lên — Gemini Vision OCR');
    expect(primaryBundle.evidence.aiMetadata?.executionPath).toBe('PRIMARY_MODEL');

    // 2. Primary 404 -> Fallback gemini-3.1-flash-lite succeeds
    vi.restoreAllMocks();
    resetGeminiResilienceForTest();
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            error: { message: 'model not found for key AIzaSySandboxSecretNeverLeak999999' },
          }),
          { status: 404, headers: { 'Content-Type': 'application/json' } }
        )
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            candidates: [
              {
                content: {
                  parts: [
                    {
                      text: JSON.stringify({
                        ocrExtractedTextVi: 'OCR từ mô hình dự phòng 3.1',
                        recipientAccountNumber: '1903888999222',
                        recipientOwnerName: 'TRAN VAN FALLBACK',
                        amountVnd: 12000000,
                        scamArchetypeVi: 'Giả danh Shipper mô phỏng',
                        extractedSignals: ['Link lạ'],
                      }),
                    },
                  ],
                },
              },
            ],
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        )
      );

    const fallbackRes = await extractSandboxEntitiesWithGeminiVision('', VALID_32X32_PNG_DATA_URL);
    expect(fallbackRes.aiMetadata?.executionPath).toBe('FALLBACK_MODEL');
    expect(fallbackRes.aiMetadata?.fallbackReason).toBe('MODEL_UNAVAILABLE');
    expect(JSON.stringify(fallbackRes.aiMetadata)).not.toContain('AIzaSySandboxSecretNeverLeak999999');
    const fallbackBundle = synthesizeSandboxCase({
      rawTranscript: '',
      imageDataUrl: VALID_32X32_PNG_DATA_URL,
      extractedOverrides: fallbackRes,
      existingAccounts: SEED_ACCOUNTS,
    });
    expect(fallbackBundle.evidence.title).toBe('Ảnh bằng chứng tải lên — Gemini Vision Dự phòng');

    // 3. Gemini disabled/unconfigured with transcript + image -> DETERMINISTIC_FALLBACK (NEVER claims Gemini Vision OCR!)
    delete process.env.GEMINI_API_KEY;
    process.env.AEGIS_E2E_DISABLE_EXTERNAL_AI = 'true';
    const detRes = await extractSandboxEntitiesWithGeminiVision(
      'Chuyển 18 triệu vào STK 1903999888777',
      VALID_32X32_PNG_DATA_URL
    );
    expect(detRes.aiMetadata?.executionPath).toBe('DETERMINISTIC_FALLBACK');
    const detBundle = synthesizeSandboxCase({
      rawTranscript: 'Chuyển 18 triệu vào STK 1903999888777',
      imageDataUrl: VALID_32X32_PNG_DATA_URL,
      extractedOverrides: detRes,
      existingAccounts: SEED_ACCOUNTS,
    });
    expect(detBundle.evidence.title).toBe('Ảnh bằng chứng tải lên — Xử lý Mô phỏng Định lượng');
    expect(detBundle.evidence.title).not.toContain('Gemini');

    // 4. Gemini unconfigured with image-only (empty transcript) -> AI_UNAVAILABLE
    const unavailRes = await extractSandboxEntitiesWithGeminiVision('', VALID_32X32_PNG_DATA_URL);
    expect(unavailRes.aiMetadata?.executionPath).toBe('AI_UNAVAILABLE');
    const unavailBundle = synthesizeSandboxCase({
      rawTranscript: '',
      imageDataUrl: VALID_32X32_PNG_DATA_URL,
      extractedOverrides: unavailRes,
      existingAccounts: SEED_ACCOUNTS,
    });
    expect(unavailBundle.evidence.title).toBe('Ảnh bằng chứng tải lên — Chưa trích xuất bằng AI');
    expect(unavailBundle.evidence.title).not.toContain('Gemini');

    // 5. Legacy historical bundle without aiMetadata -> neutral synthetic title
    const legacyBundle = synthesizeSandboxCase({
      rawTranscript: 'Legacy sample',
      imageDataUrl: VALID_32X32_PNG_DATA_URL,
      existingAccounts: SEED_ACCOUNTS,
    });
    expect(legacyBundle.evidence.title).toBe('Ảnh bằng chứng tải lên — Xử lý Mô phỏng');
  });

  it('returns extractionAiMetadata from /api/sandbox and preserves aiMetadata from /api/copilot', async () => {
    process.env.AEGIS_E2E_DISABLE_EXTERNAL_AI = 'true';
    delete process.env.GEMINI_API_KEY;
    const sid = `sbx-prov-${Date.now()}`;

    const sbxRes = await sandboxPost(
      makeSignedRequest({
        path: '/api/sandbox',
        body: { imageDataUrl: VALID_32X32_PNG_DATA_URL, amountVnd: 15000000 },
        sessionId: sid,
        clientIp: '198.51.100.50',
      })
    );
    expect(sbxRes.status).toBe(200);
    const sbxJson = await sbxRes.json();
    expect(sbxJson.extractionAiMetadata?.executionPath).toBe('AI_UNAVAILABLE');
    expect(sbxJson.delta?.customEvidences?.[0]?.title).toBe(
      'Ảnh bằng chứng tải lên — Chưa trích xuất bằng AI'
    );

    const copRes = await copilotPost(
      makeSignedRequest({
        path: '/api/copilot',
        body: { alertId: 'ALT-APP-003', question: 'Phân tích nhanh vụ việc?' },
        sessionId: sid,
        clientIp: '198.51.100.50',
      })
    );
    expect(copRes.status).toBe(200);
    const copJson = await copRes.json();
    expect(copJson.aiMetadata?.executionPath).toBe('DETERMINISTIC_FALLBACK');
    expect(copJson.aiMetadata?.fallbackReason).toBe('UNCONFIGURED');
  });
});

describe('Wave B1.0.3.1 — Phases 3 & 4: Safe Global Quota Parsing, Cross-Route Quota & Fallback Readiness (B103R-QUOTA-01, B103R-AI-01)', () => {
  it('strictly validates GEMINI_GLOBAL_RPM_LIMIT and GEMINI_GLOBAL_OCR_RPM_LIMIT against malformed inputs without ever producing NaN', () => {
    expect(parseStrictPositiveIntEnv(undefined, 30, 1, 10_000)).toEqual({
      value: 30,
      valid: true,
      malformed: false,
      source: 'DEFAULT',
    });
    expect(parseStrictPositiveIntEnv('45', 30, 1, 10_000)).toEqual({
      value: 45,
      valid: true,
      malformed: false,
      source: 'ENV',
    });

    for (const bad of ['', '   ', 'abc', '12.5', '-5', '0', 'Infinity', '99999999999999999999']) {
      const parsed = parseStrictPositiveIntEnv(bad, 30, 1, 10_000);
      expect(parsed.valid).toBe(false);
      expect(parsed.malformed).toBe(true);
      expect(parsed.value).toBe(30);
      expect(Number.isNaN(parsed.value)).toBe(false);
    }

    const cfg = resolveGlobalGeminiQuotaConfig({
      ...process.env,
      GEMINI_GLOBAL_RPM_LIMIT: 'abc',
      GEMINI_GLOBAL_OCR_RPM_LIMIT: '8',
    });
    expect(cfg.hasMalformedConfig).toBe(true);
    expect(cfg.rpmValid).toBe(false);
    expect(cfg.ocrValid).toBe(true);
    expect(cfg.globalRpmMax).toBe(30);
    expect(cfg.globalOcrRpmMax).toBe(8);
  });

  it('fails closed in strict mode when GEMINI_GLOBAL_RPM_LIMIT is malformed and shares global RPM + OCR counters atomically across routes and instances', async () => {
    const upstash = new SharedUpstashLuaMock();
    process.env.UPSTASH_REDIS_REST_URL = 'https://mock-upstash.upstash.io';
    process.env.UPSTASH_REDIS_REST_TOKEN = 'mock-upstash-token';
    process.env.AEGIS_REQUIRE_DISTRIBUTED_RATE_LIMIT = 'true';
    process.env.GEMINI_API_KEY = 'AIzaSyGlobalQuotaMultiRouteKey12345';
    process.env.GEMINI_QUOTA_SCOPE_ID = 'proj-contest-global-shared';
    process.env.AEGIS_E2E_DISABLE_EXTERNAL_AI = 'false';

    let geminiCalls = 0;
    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.startsWith('https://mock-upstash.upstash.io')) {
        return Promise.resolve(upstash.handle(url, init));
      }
      geminiCalls += 1;
      return Promise.resolve(
        new Response(
          JSON.stringify({
            candidates: [{ content: { parts: [{ text: 'OK reply' }] } }],
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        )
      );
    });

    // 1. Malformed GEMINI_GLOBAL_RPM_LIMIT='abc' in strict mode -> fails closed BEFORE calling Gemini or passing NaN to Lua
    process.env.GEMINI_GLOBAL_RPM_LIMIT = 'abc';
    const instBad = createGeminiResilienceInstance('inst-malformed');
    const badRes = await instBad.executeGenerateContent({
      model: 'gemini-3.5-flash-lite',
      parts: [{ text: 'hello' }],
      jsonMode: false,
      operationKind: 'INVESTIGATION',
    });
    expect(badRes.ok).toBe(false);
    expect(badRes.failClosedRedisError).toBe(true);
    expect(geminiCalls).toBe(0);
    expect(upstash.seenRpmLimits.includes('NaN')).toBe(false);

    // 2. Valid global RPM=2, OCR RPM=1 shared across two distinct instances & concurrent reservations
    process.env.GEMINI_GLOBAL_RPM_LIMIT = '2';
    process.env.GEMINI_GLOBAL_OCR_RPM_LIMIT = '1';
    const instA = createGeminiResilienceInstance('inst-A');
    const instB = createGeminiResilienceInstance('inst-B');

    const [r1, r2, r3] = await Promise.all([
      instA.executeGenerateContent({
        model: 'gemini-3.5-flash-lite',
        parts: [{ text: 'req-1' }],
        jsonMode: false,
        operationKind: 'VISION_OCR',
      }),
      instB.executeGenerateContent({
        model: 'gemini-3.5-flash-lite',
        parts: [{ text: 'req-2' }],
        jsonMode: false,
        operationKind: 'VISION_OCR', // Exceeds OCR=1!
      }),
      instB.executeGenerateContent({
        model: 'gemini-3.5-flash-lite',
        parts: [{ text: 'req-3' }],
        jsonMode: false,
        operationKind: 'COPILOT', // Uses remaining 2nd global RPM slot!
      }),
    ]);

    expect(r1.ok).toBe(true);
    expect(r2.ok).toBe(false);
    expect(r2.distributedQuotaTripped).toBe(true);
    expect(r3.ok).toBe(true);
    expect(geminiCalls).toBe(2);

    // 4th request exceeds global RPM=2 and never calls Gemini
    const r4 = await instA.executeGenerateContent({
      model: 'gemini-3.5-flash-lite',
      parts: [{ text: 'req-4' }],
      jsonMode: false,
      operationKind: 'INVESTIGATION',
    });
    expect(r4.ok).toBe(false);
    expect(r4.distributedQuotaTripped).toBe(true);
    expect(geminiCalls).toBe(2);
  });

  it('enforces explicit GEMINI_FALLBACK_MODEL readiness guard on production / explicit flag while keeping local dev backward-compatible', async () => {
    delete process.env.GEMINI_FALLBACK_MODEL;
    delete process.env.VERCEL_ENV;
    delete process.env.AEGIS_REQUIRE_EXPLICIT_GEMINI_FALLBACK;
    process.env.GEMINI_API_KEY = 'AIzaSyHealthReadinessKey1234567890';
    process.env.AEGIS_E2E_DISABLE_EXTERNAL_AI = 'false';

    // Non-strict dev: legacy fallback allowed, fallbackSource='DEFAULT'
    const devStatus = evaluateGeminiFallbackReadiness();
    expect(devStatus.fallbackReady).toBe(true);
    expect(devStatus.fallbackModel).toBe('gemini-2.5-flash-lite');
    expect(devStatus.fallbackSource).toBe('DEFAULT');

    // Explicit flag or Vercel production with missing/empty GEMINI_FALLBACK_MODEL -> NOT READY (503)
    process.env.AEGIS_REQUIRE_EXPLICIT_GEMINI_FALLBACK = 'true';
    process.env.GEMINI_FALLBACK_MODEL = '   ';
    const strictMissing = evaluateGeminiFallbackReadiness();
    expect(strictMissing.fallbackReady).toBe(false);
    expect(strictMissing.warningCode).toBe('LEGACY_DEFAULT_FALLBACK_IN_STRICT_MODE');

    const healthMissingRes = await healthGet(new NextRequest('http://localhost:3000/api/health'));
    expect(healthMissingRes.status).toBe(503);
    const healthMissingJson = await healthMissingRes.json();
    expect(healthMissingJson.readinessOk).toBe(false);
    expect(healthMissingJson.dependencies.fallbackModelReady).toBe(false);
    expect(JSON.stringify(healthMissingJson)).not.toContain('AIzaSyHealthReadinessKey1234567890');

    // Explicit GEMINI_FALLBACK_MODEL=gemini-3.1-flash-lite -> READY (200)
    process.env.GEMINI_FALLBACK_MODEL = 'gemini-3.1-flash-lite';
    const healthOkRes = await healthGet(new NextRequest('http://localhost:3000/api/health'));
    expect(healthOkRes.status).toBe(200);
    const healthOkJson = await healthOkRes.json();
    expect(healthOkJson.readinessOk).toBe(true);
    expect(healthOkJson.fallbackModel).toBe('gemini-3.1-flash-lite');
    expect(healthOkJson.fallbackSource).toBe('GEMINI_FALLBACK_MODEL');
  });
});

describe('Wave B1.0.3.1 — Phases 5 & 6: Async Effect Coordinator, Distinct Proxy IP Separation & Error Sanitization', () => {
  it('aborts and rejects stale in-flight async operations after Reset Demo, session rotation, or unmount', () => {
    const coord = createWorkspaceAsyncCoordinator('sess-A');
    const opSandbox = coord.beginOperation('sess-A');
    expect(coord.isCurrent(opSandbox)).toBe(true);
    expect(coord.getInFlightCount()).toBe(1);

    // Trigger Reset Demo while Sandbox request is still in flight
    coord.invalidateAll('sess-A');
    expect(opSandbox.controller.signal.aborted).toBe(true);
    expect(coord.isCurrent(opSandbox)).toBe(false);
    expect(coord.getInFlightCount()).toBe(0);

    // Start new op on rotated session B -> unmount disposes and aborts cleanly
    const opB = coord.beginOperation('sess-B');
    coord.invalidateAll('sess-B');
    expect(coord.isCurrent(opB)).toBe(false);

    const opB2 = coord.beginOperation('sess-B');
    expect(coord.isCurrent(opB2)).toBe(true);
    coord.dispose();
    expect(opB2.controller.signal.aborted).toBe(true);
    expect(coord.isCurrent(opB2)).toBe(false);
  });

  it('enforces distinct IP burst buckets via trusted x-real-ip header and sanitizes unexpected API route catch errors', async () => {
    const upstash = new SharedUpstashLuaMock();
    process.env.UPSTASH_REDIS_REST_URL = 'https://mock-upstash.upstash.io';
    process.env.UPSTASH_REDIS_REST_TOKEN = 'mock-upstash-token';
    process.env.AEGIS_REQUIRE_DISTRIBUTED_RATE_LIMIT = 'true';
    process.env.TRUST_PROXY_HEADERS = 'true';
    process.env.AEGIS_E2E_DISABLE_EXTERNAL_AI = 'true';
    process.env.AI_RATE_LIMIT_PER_MIN = '2';
    process.env.AI_IP_BURST_LIMIT_PER_MIN = '2';

    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = typeof input === 'string' ? input : input.toString();
      return Promise.resolve(upstash.handle(url, init));
    });

    // IP-1 uses both IP burst slots across 2 sessions -> 3rd call on IP-1 hits 429 IP
    const ip1 = '203.0.113.101';
    const ip2 = '203.0.113.202';
    expect(
      (
        await investigatePost(
          makeSignedRequest({
            path: '/api/investigate',
            body: { alertId: 'ALT-APP-003' },
            sessionId: `s1-${Date.now()}`,
            clientIp: ip1,
          })
        )
      ).status
    ).toBe(200);
    expect(
      (
        await investigatePost(
          makeSignedRequest({
            path: '/api/investigate',
            body: { alertId: 'ALT-APP-003' },
            sessionId: `s2-${Date.now()}`,
            clientIp: ip1,
          })
        )
      ).status
    ).toBe(200);

    const ip1Blocked = await investigatePost(
      makeSignedRequest({
        path: '/api/investigate',
        body: { alertId: 'ALT-APP-003' },
        sessionId: `s3-${Date.now()}`,
        clientIp: ip1,
      })
    );
    expect(ip1Blocked.status).toBe(429);
    expect((await ip1Blocked.json()).limitScope).toBe('IP');

    // Distinct IP-2 MUST STILL SUCCEED (proves x-real-ip separation works)
    const ip2Allowed = await investigatePost(
      makeSignedRequest({
        path: '/api/investigate',
        body: { alertId: 'ALT-APP-003' },
        sessionId: `s4-${Date.now()}`,
        clientIp: ip2,
      })
    );
    expect(ip2Allowed.status).toBe(200);

    // Unexpected internal Error in route catch block MUST NOT leak raw err.message
    const leakingAdapter = new InMemoryPersistenceAdapter();
    vi.spyOn(leakingAdapter, 'loadSession').mockRejectedValue(
      new Error('INTERNAL_SQL_SECRET_LEAK_XYZ_999')
    );
    setPersistenceAdapterForTest(leakingAdapter);

    const errInv = await investigatePost(
      makeSignedRequest({
        path: '/api/investigate',
        body: { alertId: 'ALT-APP-003' },
        sessionId: `s5-${Date.now()}`,
        clientIp: '198.51.100.88',
      })
    );
    expect(errInv.status).toBe(400);
    const errInvText = await errInv.text();
    expect(errInvText).not.toContain('INTERNAL_SQL_SECRET_LEAK_XYZ_999');

    const errVision = await merchantVisionPost(
      makeSignedRequest({
        path: '/api/merchant/vision',
        body: { imageDataUrl: VALID_32X32_PNG_DATA_URL },
        sessionId: `s6-${Date.now()}`,
        clientIp: '198.51.100.89',
      })
    );
    expect(errVision.status).toBe(400);
    const errVisionText = await errVision.text();
    expect(errVisionText).not.toContain('INTERNAL_SQL_SECRET_LEAK_XYZ_999');
  });
});

describe('Wave B1.0.3.2 — React Strict Mode Coordinator Recovery & Bounded Multi-Batch Cleanup (B1031R-REACT-01, B1031R-CLEANUP-01)', () => {
  it('recovers the SAME coordinator instance across React Strict Mode setup -> dispose -> remount without resurrecting pre-cleanup operations', () => {
    const coord = createWorkspaceAsyncCoordinator('sess-strict-1');
    coord.activate();
    expect(coord.isActive()).toBe(true);

    // Mount 1 starts bootstrap operation
    const opMount1 = coord.beginOperation('sess-strict-1');
    expect(coord.isCurrent(opMount1)).toBe(true);

    // Strict Mode simulated unmount disposes the coordinator
    coord.dispose();
    expect(coord.isActive()).toBe(false);
    expect(opMount1.controller.signal.aborted).toBe(true);
    expect(coord.isCurrent(opMount1)).toBe(false);

    // Strict Mode simulated remount reactivates the EXACT SAME coordinator instance
    coord.activate();
    coord.activate(); // idempotent
    expect(coord.isActive()).toBe(true);

    // Pre-cleanup operation MUST remain permanently invalid even after reactivation
    expect(coord.isCurrent(opMount1)).toBe(false);

    // Mount 2 starts fresh bootstrap operation on the same coordinator -> MUST be accepted
    const opMount2 = coord.beginOperation('sess-strict-1');
    expect(coord.isCurrent(opMount2)).toBe(true);
    expect(opMount2.epoch).toBeGreaterThan(opMount1.epoch);

    // Delayed Reset Demo during pending opMount2 invalidates opMount2 cleanly
    coord.invalidateAll('sess-strict-1');
    expect(opMount2.controller.signal.aborted).toBe(true);
    expect(coord.isCurrent(opMount2)).toBe(false);

    // New operation after Reset Demo succeeds, then genuine unmount disposes permanently until next mount
    const opAfterReset = coord.beginOperation('sess-strict-1');
    expect(coord.isCurrent(opAfterReset)).toBe(true);
    coord.dispose();
    coord.dispose(); // idempotent
    expect(coord.isActive()).toBe(false);
    expect(coord.isCurrent(opAfterReset)).toBe(false);
  });

  it('drains multiple bounded cleanup batches (100 + 100 + 35 = 235), stops on partial/empty batches, and enforces maxBatches and timeBudgetMs caps', async () => {
    // 1. Multiple batches terminating cleanly on partial batch (100 + 100 + 35 = 235)
    const batchCounts = [100, 100, 35];
    let callIdx = 0;
    const multiBatchAdapter = {
      mode: 'POSTGRES' as const,
      purgeExpiredSessions: vi.fn(async ({ batchSize = 100 }) => {
        const count = batchCounts[callIdx++] ?? 0;
        return { purgedCount: count, batchLimit: batchSize, mode: 'POSTGRES' as const };
      }),
    };
    const drainOk = await runBoundedExpiredSessionDrain(multiBatchAdapter, {
      batchSize: 100,
      maxBatches: 10,
      timeBudgetMs: 8_000,
    });
    expect(drainOk.purgedCount).toBe(235);
    expect(drainOk.batchesExecuted).toBe(3);
    expect(drainOk.batchLimitReached).toBe(false);
    expect(drainOk.budgetExhausted).toBe(false);
    expect(drainOk.hasMoreExpiredPossible).toBe(false);
    expect(multiBatchAdapter.purgeExpiredSessions).toHaveBeenCalledTimes(3);

    // 2. Empty batch stops immediately after 1 query
    const emptyAdapter = {
      mode: 'POSTGRES' as const,
      purgeExpiredSessions: vi.fn(async ({ batchSize = 100 }) => ({
        purgedCount: 0,
        batchLimit: batchSize,
        mode: 'POSTGRES' as const,
      })),
    };
    const drainEmpty = await runBoundedExpiredSessionDrain(emptyAdapter);
    expect(drainEmpty.purgedCount).toBe(0);
    expect(drainEmpty.batchesExecuted).toBe(1);
    expect(drainEmpty.hasMoreExpiredPossible).toBe(false);

    // 3. Max batch limit cap (10 full batches = 1,000 rows max)
    const endlessAdapter = {
      mode: 'POSTGRES' as const,
      purgeExpiredSessions: vi.fn(async ({ batchSize = 100 }) => ({
        purgedCount: batchSize,
        batchLimit: batchSize,
        mode: 'POSTGRES' as const,
      })),
    };
    const drainMax = await runBoundedExpiredSessionDrain(endlessAdapter, {
      batchSize: 100,
      maxBatches: 10,
      timeBudgetMs: 8_000,
    });
    expect(drainMax.purgedCount).toBe(1_000);
    expect(drainMax.batchesExecuted).toBe(10);
    expect(drainMax.batchLimitReached).toBe(true);
    expect(drainMax.hasMoreExpiredPossible).toBe(true);
    expect(endlessAdapter.purgeExpiredSessions).toHaveBeenCalledTimes(10);

    // 4. Deterministic wall-clock budget exhaustion (no flaky setTimeout)
    let fakeClockMs = 0;
    const slowAdapter = {
      mode: 'POSTGRES' as const,
      purgeExpiredSessions: vi.fn(async ({ batchSize = 100 }) => {
        fakeClockMs += 4_500;
        return { purgedCount: batchSize, batchLimit: batchSize, mode: 'POSTGRES' as const };
      }),
    };
    const drainBudget = await runBoundedExpiredSessionDrain(slowAdapter, {
      batchSize: 100,
      maxBatches: 10,
      timeBudgetMs: 8_000,
      nowMs: () => fakeClockMs,
    });
    expect(drainBudget.batchesExecuted).toBe(2); // 4500ms after batch 1 (<8000), 9000ms after batch 2 (>=8000 -> stops!)
    expect(drainBudget.purgedCount).toBe(200);
    expect(drainBudget.budgetExhausted).toBe(true);
    expect(drainBudget.hasMoreExpiredPossible).toBe(true);
    expect(slowAdapter.purgeExpiredSessions).toHaveBeenCalledTimes(2);
  });

  it('handles mid-drain DB failure honestly without leaking raw SQL errors and supports safe concurrent cleanup invocations', async () => {
    const dedicatedCronSecret = 'z'.repeat(48);
    process.env.CRON_SECRET = dedicatedCronSecret;
    delete process.env.AEGIS_SESSION_SECRET;

    // 1. Mid-drain failure on batch 2 after batch 1 deleted 100 rows
    let batchNum = 0;
    const failingAdapter = new InMemoryPersistenceAdapter();
    vi.spyOn(failingAdapter, 'purgeExpiredSessions').mockImplementation(async ({ batchSize = 100 } = {}) => {
      batchNum += 1;
      if (batchNum === 1) {
        return { purgedCount: batchSize, batchLimit: batchSize, mode: 'POSTGRES' };
      }
      throw new Error('PG_INTERNAL_SENSITIVE_SQL_DETAIL_SECRET_888');
    });
    setPersistenceAdapterForTest(failingAdapter);

    const partialRes = await cleanupGet(
      new NextRequest('http://localhost:3000/api/internal/cleanup?batchSize=999999', {
        headers: { authorization: `Bearer ${dedicatedCronSecret}` },
      })
    );
    expect(partialRes.status).toBe(500);
    const partialText = await partialRes.text();
    expect(partialText).not.toContain('PG_INTERNAL_SENSITIVE_SQL_DETAIL_SECRET_888');
    const partialJson = JSON.parse(partialText);
    expect(partialJson.ok).toBe(false);
    expect(partialJson.purgedCount).toBe(100);
    expect(partialJson.batchesExecuted).toBe(1);
    expect(partialJson.batchSize).toBe(100); // query param ignored
    expect(partialJson.hasMoreExpiredPossible).toBe(true);

    // 2. Concurrent cleanup invocations against Postgres spy pool -> zero double-counting & active preserved
    const spyPool = new RetentionSpyPool();
    const pgAdapter = new PostgresPersistenceAdapter(spyPool);
    const nowMs = Date.now();
    for (let i = 0; i < 150; i += 1) {
      spyPool.rows.set(`exp-${i}`, {
        session_id: `exp-${i}`,
        status: 'ACTIVE',
        delta_json: {},
        delta_integrity_tag: '',
        expires_at: new Date(nowMs - (i + 1) * 10_000).toISOString(),
        revoked_at: null,
      });
    }
    spyPool.rows.set('active-keep', {
      session_id: 'active-keep',
      status: 'ACTIVE',
      delta_json: {},
      delta_integrity_tag: 'ok',
      expires_at: new Date(nowMs + 3_600_000).toISOString(),
      revoked_at: null,
    });
    setPersistenceAdapterForTest(pgAdapter);

    const [c1, c2] = await Promise.all([
      cleanupGet(
        new NextRequest('http://localhost:3000/api/internal/cleanup', {
          headers: { authorization: `Bearer ${dedicatedCronSecret}` },
        })
      ),
      cleanupPost(
        new NextRequest('http://localhost:3000/api/internal/cleanup', {
          method: 'POST',
          headers: { authorization: `Bearer ${dedicatedCronSecret}` },
        })
      ),
    ]);
    expect(c1.status).toBe(200);
    expect(c2.status).toBe(200);
    const j1 = await c1.json();
    const j2 = await c2.json();
    expect(j1.purgedCount + j2.purgedCount).toBe(150);
    expect(spyPool.rows.has('active-keep')).toBe(true);
    expect(spyPool.rows.size).toBe(1);
  });
});
