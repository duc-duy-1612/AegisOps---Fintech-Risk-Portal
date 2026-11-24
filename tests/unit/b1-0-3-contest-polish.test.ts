import { afterEach, describe, expect, it, vi } from 'vitest';
import { NextRequest } from 'next/server';
import { POST as copilotPost } from '@/app/api/copilot/route';
import { POST as investigatePost } from '@/app/api/investigate/route';
import { POST as merchantVisionPost } from '@/app/api/merchant/vision/route';
import { POST as sandboxPost } from '@/app/api/sandbox/route';
import { runDeterministicForensicsSuite } from '@/domain/forensics-analyzers';
import { resolvePublicAiRouteLimits } from '@/infrastructure/distributed-rate-limiter';
import {
  askGeminiCopilotOnCase,
  extractMerchantBillWithGeminiVision,
  runGeminiInvestigationWithFallback,
} from '@/infrastructure/gemini-agent';
import { resetGeminiResilienceForTest } from '@/infrastructure/gemini-resilience';
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
  createSignedSessionToken,
} from '@/infrastructure/session-auth';

/**
 * Stateful in-memory Upstash Redis REST simulator supporting `/multi-exec` and `/eval`
 * for verifying shared-NAT layered rate limiting and global Gemini quota coordination.
 */
class StatefulUpstashMock {
  public readonly counters = new Map<string, number>();
  public readonly strings = new Map<string, string>();
  public readonly incrementedKeys: string[] = [];

  public handleRequest(url: string, init?: RequestInit): Response {
    const bodyText = typeof init?.body === 'string' ? init.body : '';
    if (url.endsWith('/multi-exec')) {
      const commands = JSON.parse(bodyText) as unknown[][];
      const results = commands.map((cmd) => {
        const op = String(cmd[0] ?? '').toUpperCase();
        if (op === 'EVAL') {
          const numKeys = Number(cmd[2] ?? 0);
          const keys = cmd.slice(3, 3 + numKeys).map(String);
          const argv = cmd.slice(3 + numKeys);
          const rpmKey = keys[6] ?? 'rpm';
          const ocrKey = keys[8] ?? 'ocr';
          const rpmMax = Number(argv[1] ?? 30);
          const ocrMax = Number(argv[2] ?? 12);
          const isOcr = String(argv[3] ?? '0') === '1';
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
          this.incrementedKeys.push(rpmKey);
          return { result: ['ALLOWED', String(nextRpm), '0'] };
        }
        const key = String(cmd[1] ?? '');
        if (op === 'INCR') {
          const next = (this.counters.get(key) ?? 0) + 1;
          this.counters.set(key, next);
          this.incrementedKeys.push(key);
          return { result: next };
        }
        if (op === 'PEXPIRE') {
          return { result: 1 };
        }
        if (op === 'GET') {
          return { result: this.strings.get(key) ?? null };
        }
        if (op === 'SET') {
          this.strings.set(key, String(cmd[2] ?? ''));
          return { result: 'OK' };
        }
        return { result: 1 };
      });
      return new Response(JSON.stringify(results), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // Atomic Lua `/eval` used by Gemini global quota + circuit gate
    if (url.includes('/eval')) {
      const payload = JSON.parse(bodyText) as unknown[];
      // Upstash REST format: [script, numKeys, key1, key2, key3, key4, arg1, arg2, arg3, arg4, arg5, arg6]
      const numKeys = Number(payload[1] ?? 0);
      const keys = payload.slice(2, 2 + numKeys).map(String);
      const args = payload.slice(2 + numKeys);
      const rpmKey = keys[1] ?? 'rpm';
      const ocrKey = keys[2] ?? 'ocr';
      const globalRpmLimit = Number(args[1] ?? 30);
      const isOcr = Number(args[2] ?? 0) === 1;
      const globalOcrLimit = Number(args[3] ?? 12);

      const nextRpm = (this.counters.get(rpmKey) ?? 0) + 1;
      this.counters.set(rpmKey, nextRpm);
      if (nextRpm > globalRpmLimit) {
        return new Response(JSON.stringify({ result: ['GLOBAL_RPM_EXCEEDED', 60_000, ''] }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      if (isOcr) {
        const nextOcr = (this.counters.get(ocrKey) ?? 0) + 1;
        this.counters.set(ocrKey, nextOcr);
        if (nextOcr > globalOcrLimit) {
          return new Response(JSON.stringify({ result: ['GLOBAL_OCR_RPM_EXCEEDED', 60_000, ''] }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          });
        }
      }
      return new Response(JSON.stringify({ result: ['ALLOW', 0, ''] }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    return new Response(JSON.stringify({ result: 'OK' }), { status: 200 });
  }
}

const VALID_32X32_PNG_BASE64 = (() => {
  // Minimal valid PNG header (32x32 RGB) + empty IDAT + IEND (>= 24 bytes, passes magic/IHDR checks)
  const buf = Buffer.from([
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, // PNG signature
    0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52, // IHDR length + type
    0x00, 0x00, 0x00, 0x20, // width = 32
    0x00, 0x00, 0x00, 0x20, // height = 32
    0x08, 0x02, 0x00, 0x00, 0x00, // 8-bit RGB
    0xfc, 0x18, 0xed, 0xa3, // CRC
    0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82, // IEND
  ]);
  return buf.toString('base64');
})();

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

const buildSampleForensics = () => {
  const alert = SEED_ALERTS[0]!;
  const forensics = runDeterministicForensicsSuite({
    alert,
    accounts: SEED_ACCOUNTS,
    transactions: SEED_TRANSACTIONS,
    authLogs: SEED_AUTH_LOGS,
    devices: SEED_DEVICES,
    apiEvents: SEED_API_EVENTS,
    evidences: SEED_EVIDENCES,
  });
  return { alert, forensics };
};

const makeSignedAiRequest = (params: {
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

afterEach(() => {
  vi.restoreAllMocks();
  restoreEnv();
  resetGeminiResilienceForTest();
});

describe('Wave B1.0.3 — Phase 2: Sanitized AI Fallback Transparency', () => {
  it('returns PRIMARY_MODEL metadata without fallback notice when primary Gemini succeeds', async () => {
    process.env.GEMINI_API_KEY = 'AIzaSyFakeTestKeyPrimarySuccess999';
    process.env.GEMINI_PRIMARY_MODEL = 'gemini-3.5-flash-lite';
    process.env.GEMINI_FALLBACK_MODEL = 'gemini-3.1-flash-lite';
    process.env.AEGIS_E2E_DISABLE_EXTERNAL_AI = 'false';

    const { alert, forensics } = buildSampleForensics();
    const validBriefJson = JSON.stringify({
      classification: forensics.fallbackReport.classification,
      confidenceScore: 93,
      executiveSummaryVi: 'Xác nhận kịch bản APP Fraud dựa trên bằng chứng đối soát.',
      keyFindingsVi: [`Phát hiện bằng chứng ${forensics.validEvidenceIds[0]}`],
      citedEvidenceIds: forensics.validEvidenceIds.slice(0, 2),
      userShieldWarningVi: 'Cảnh báo lừa đảo giả danh.',
      recommendedActions: forensics.fallbackReport.recommendedActions,
    });

    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          candidates: [{ content: { parts: [{ text: validBriefJson }] } }],
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } }
      )
    );

    const report = await runGeminiInvestigationWithFallback({
      alert,
      forensics,
      evidenceTranscript: 'Kịch bản mô phỏng giả danh cán bộ.',
    });

    expect(report.modelUsed).toBe('gemini-3.5-flash-lite');
    expect(report.aiMetadata?.executionPath).toBe('PRIMARY_MODEL');
    expect(report.aiMetadata?.primaryModel).toBe('gemini-3.5-flash-lite');
    expect(report.aiMetadata?.fallbackReason).toBeUndefined();
    expect(report.aiMetadata?.userNoticeVi).toBeUndefined();
  });

  it('surfaces FALLBACK_MODEL metadata with sanitized MODEL_UNAVAILABLE reason when primary returns 404', async () => {
    process.env.GEMINI_API_KEY = 'AIzaSySecretKeyNeverLeak123456789';
    process.env.GEMINI_PRIMARY_MODEL = 'gemini-3.5-flash-lite';
    process.env.GEMINI_FALLBACK_MODEL = 'gemini-3.1-flash-lite';
    process.env.AEGIS_E2E_DISABLE_EXTERNAL_AI = 'false';

    const { alert, forensics } = buildSampleForensics();
    const validBriefJson = JSON.stringify({
      classification: forensics.fallbackReport.classification,
      confidenceScore: 91,
      executiveSummaryVi: 'Kết luận từ mô hình dự phòng 3.1 flash lite.',
      keyFindingsVi: [`Bằng chứng ${forensics.validEvidenceIds[0]}`],
      citedEvidenceIds: forensics.validEvidenceIds.slice(0, 2),
      userShieldWarningVi: 'Cảnh báo giao dịch rủi ro cao.',
      recommendedActions: forensics.fallbackReport.recommendedActions,
    });

    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            error: {
              message:
                'models/gemini-3.5-flash-lite not found for key AIzaSySecretKeyNeverLeak123456789 stack /internal/srv/auth.ts',
            },
          }),
          { status: 404, headers: { 'Content-Type': 'application/json' } }
        )
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            candidates: [{ content: { parts: [{ text: validBriefJson }] } }],
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        )
      );

    const report = await runGeminiInvestigationWithFallback({
      alert,
      forensics,
      evidenceTranscript: 'Kịch bản mô phỏng.',
    });

    expect(report.modelUsed).toBe('gemini-3.1-flash-lite');
    expect(report.aiMetadata?.executionPath).toBe('FALLBACK_MODEL');
    expect(report.aiMetadata?.fallbackReason).toBe('MODEL_UNAVAILABLE');
    expect(report.aiMetadata?.userNoticeVi).toContain('gemini-3.1-flash-lite');
    // Must NEVER leak raw API keys, provider error text, or stack paths
    const serialized = JSON.stringify(report.aiMetadata);
    expect(serialized).not.toContain('AIzaSySecretKeyNeverLeak123456789');
    expect(serialized).not.toContain('/internal/srv/auth.ts');
  });

  it('surfaces DETERMINISTIC_FALLBACK with TIMEOUT and QUOTA_EXCEEDED reasons safely', async () => {
    process.env.GEMINI_API_KEY = 'AIzaSySecretKeyNeverLeak987654321';
    process.env.GEMINI_PRIMARY_MODEL = 'gemini-3.5-flash-lite';
    process.env.GEMINI_FALLBACK_MODEL = 'gemini-3.1-flash-lite';
    process.env.AEGIS_E2E_DISABLE_EXTERNAL_AI = 'false';

    const { alert, forensics } = buildSampleForensics();

    // 1. Both models time out -> DETERMINISTIC_FALLBACK + TIMEOUT
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => {
      const abortErr = new Error('The operation was aborted');
      abortErr.name = 'AbortError';
      return Promise.reject(abortErr);
    });

    const timeoutReport = await runGeminiInvestigationWithFallback({
      alert,
      forensics,
      evidenceTranscript: 'Kịch bản timeout.',
    });
    expect(timeoutReport.aiMetadata?.executionPath).toBe('DETERMINISTIC_FALLBACK');
    expect(timeoutReport.aiMetadata?.fallbackReason).toBe('TIMEOUT');
    expect(timeoutReport.aiMetadata?.userNoticeVi).toContain('Dự phòng Định lượng');

    // 2. Daily quota / RPD exhausted -> DETERMINISTIC_FALLBACK + QUOTA_EXCEEDED
    vi.restoreAllMocks();
    resetGeminiResilienceForTest();
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(
        JSON.stringify({
          error: {
            code: 429,
            status: 'RESOURCE_EXHAUSTED',
            message: 'GenerateRequestsPerDayPerProjectPerModel-FreeTier exceeded for AIzaSySecretKeyNeverLeak987654321',
          },
        }),
        { status: 429, headers: { 'Content-Type': 'application/json' } }
      )
    );

    const quotaReport = await runGeminiInvestigationWithFallback({
      alert,
      forensics,
      evidenceTranscript: 'Kịch bản quota exhausted.',
    });
    expect(quotaReport.aiMetadata?.executionPath).toBe('DETERMINISTIC_FALLBACK');
    expect(quotaReport.aiMetadata?.fallbackReason).toBe('QUOTA_EXCEEDED');
    expect(JSON.stringify(quotaReport.aiMetadata)).not.toContain('AIzaSySecretKeyNeverLeak987654321');
    expect(JSON.stringify(quotaReport.aiMetadata)).not.toContain('GenerateRequestsPerDay');
  });

  it('surfaces sanitized AI_UNAVAILABLE provenance for Merchant Vision OCR and Copilot when unconfigured', async () => {
    delete process.env.GEMINI_API_KEY;
    process.env.AEGIS_E2E_DISABLE_EXTERNAL_AI = 'true';
    const { alert, forensics } = buildSampleForensics();

    const visionRes = await extractMerchantBillWithGeminiVision({
      mimeType: 'image/png',
      base64Data: VALID_32X32_PNG_BASE64,
    });
    expect(visionRes.outcome).toBe('AI_UNAVAILABLE');
    expect(visionRes.aiMetadata.executionPath).toBe('AI_UNAVAILABLE');
    expect(visionRes.aiMetadata.fallbackReason).toBe('UNCONFIGURED');
    expect(visionRes.aiMetadata.userNoticeVi).toBeTruthy();

    const copilotRes = await askGeminiCopilotOnCase({
      question: 'Giải thích vụ việc này?',
      alert,
      forensics,
    });
    expect(copilotRes.aiMetadata.executionPath).toBe('DETERMINISTIC_FALLBACK');
    expect(copilotRes.aiMetadata.fallbackReason).toBe('UNCONFIGURED');
  });
});

describe('Wave B1.0.3 — Phase 3: Layered Shared-NAT Public AI Rate Limiting', () => {
  it('resolves tiered defaults with per-session limits strictly below shared-NAT IP burst', () => {
    delete process.env.AI_RATE_LIMIT_PER_MIN;
    delete process.env.AI_SANDBOX_RATE_LIMIT_PER_MIN;
    delete process.env.AI_OCR_RATE_LIMIT_PER_MIN;
    delete process.env.AI_IP_BURST_LIMIT_PER_MIN;

    const inv = resolvePublicAiRouteLimits('INVESTIGATE');
    const sbx = resolvePublicAiRouteLimits('SANDBOX');
    const ocr = resolvePublicAiRouteLimits('VISION_OCR');

    expect(inv.sessionMaxPerMinute).toBe(12);
    expect(sbx.sessionMaxPerMinute).toBe(8);
    expect(ocr.sessionMaxPerMinute).toBe(6);
    expect(inv.ipBurstMaxPerMinute).toBe(36);
    expect(ocr.sessionMaxPerMinute).toBeLessThan(inv.sessionMaxPerMinute);
    expect(inv.sessionMaxPerMinute).toBeLessThan(inv.ipBurstMaxPerMinute);
  });

  it('throttles a single noisy session behind shared NAT without blocking a second valid judge session on the same IP', async () => {
    const upstash = new StatefulUpstashMock();
    process.env.UPSTASH_REDIS_REST_URL = 'https://mock-upstash.upstash.io';
    process.env.UPSTASH_REDIS_REST_TOKEN = 'mock-upstash-token';
    process.env.AEGIS_REQUIRE_DISTRIBUTED_RATE_LIMIT = 'true';
    process.env.TRUST_PROXY_HEADERS = 'true';
    process.env.AEGIS_E2E_DISABLE_EXTERNAL_AI = 'true';
    process.env.AI_RATE_LIMIT_PER_MIN = '2';
    process.env.AI_IP_BURST_LIMIT_PER_MIN = '5';

    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = typeof input === 'string' ? input : input.toString();
      return Promise.resolve(upstash.handleRequest(url, init));
    });

    const sharedJudgeNatIp = '203.0.113.77';
    const sessionJudgeA = `judge-a-${Date.now()}`;
    const sessionJudgeB = `judge-b-${Date.now()}`;

    // Judge A makes 2 valid requests -> both succeed (200)
    const a1 = await investigatePost(
      makeSignedAiRequest({
        path: '/api/investigate',
        body: { alertId: 'ALT-APP-003' },
        sessionId: sessionJudgeA,
        clientIp: sharedJudgeNatIp,
      })
    );
    const a2 = await investigatePost(
      makeSignedAiRequest({
        path: '/api/investigate',
        body: { alertId: 'ALT-APP-003' },
        sessionId: sessionJudgeA,
        clientIp: sharedJudgeNatIp,
      })
    );
    expect(a1.status).toBe(200);
    expect(a2.status).toBe(200);

    // Judge A spams 4 more requests -> all blocked with 429 + limitScope=SESSION + Retry-After header
    for (let i = 0; i < 4; i++) {
      const blocked = await investigatePost(
        makeSignedAiRequest({
          path: '/api/investigate',
          body: { alertId: 'ALT-APP-003' },
          sessionId: sessionJudgeA,
          clientIp: sharedJudgeNatIp,
        })
      );
      expect(blocked.status).toBe(429);
      const retryAfter = blocked.headers.get('Retry-After');
      expect(Number(retryAfter)).toBeGreaterThan(0);
      const json = await blocked.json();
      expect(json.code).toBe('RATE_LIMITED');
      expect(json.limitScope).toBe('SESSION');
      expect(json.retryAfterSeconds).toBeGreaterThan(0);
    }

    // Judge B on the EXACT SAME shared NAT IP MUST STILL SUCCEED because Judge A's blocked spam
    // was rejected at the per-session layer BEFORE incrementing the shared-NAT IP burst counter!
    const b1 = await investigatePost(
      makeSignedAiRequest({
        path: '/api/investigate',
        body: { alertId: 'ALT-APP-003' },
        sessionId: sessionJudgeB,
        clientIp: sharedJudgeNatIp,
      })
    );
    const b2 = await investigatePost(
      makeSignedAiRequest({
        path: '/api/investigate',
        body: { alertId: 'ALT-APP-003' },
        sessionId: sessionJudgeB,
        clientIp: sharedJudgeNatIp,
      })
    );
    expect(b1.status).toBe(200);
    expect(b2.status).toBe(200);
  });

  it('prevents untrusted client body or spoofed header sessionId from bypassing verified cookie session rate limits', async () => {
    const upstash = new StatefulUpstashMock();
    process.env.UPSTASH_REDIS_REST_URL = 'https://mock-upstash.upstash.io';
    process.env.UPSTASH_REDIS_REST_TOKEN = 'mock-upstash-token';
    process.env.AEGIS_REQUIRE_DISTRIBUTED_RATE_LIMIT = 'true';
    process.env.TRUST_PROXY_HEADERS = 'true';
    process.env.AEGIS_E2E_DISABLE_EXTERNAL_AI = 'true';
    process.env.AI_RATE_LIMIT_PER_MIN = '1';
    process.env.AI_IP_BURST_LIMIT_PER_MIN = '20';

    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = typeof input === 'string' ? input : input.toString();
      return Promise.resolve(upstash.handleRequest(url, init));
    });

    const verifiedSession = `verified-sid-${Date.now()}`;
    // 1. Spoofed x-workspace-session header mismatching signed cookie is rejected fail-closed with 401
    const spoofedHeaderRes = await copilotPost(
      makeSignedAiRequest({
        path: '/api/copilot',
        body: { alertId: 'ALT-APP-003', question: 'Tóm tắt vụ việc?' },
        sessionId: verifiedSession,
        clientIp: '198.51.100.10',
        extraHeaders: { 'x-workspace-session': 'spoofed-header-1' },
      })
    );
    expect(spoofedHeaderRes.status).toBe(401);

    // 2. Valid request consumes verified cookie session quota (limit = 1)
    const r1 = await copilotPost(
      makeSignedAiRequest({
        path: '/api/copilot',
        body: { alertId: 'ALT-APP-003', question: 'Tóm tắt vụ việc?' },
        sessionId: verifiedSession,
        clientIp: '198.51.100.10',
      })
    );
    expect(r1.status).toBe(200);

    // 3. Passing an untrusted body sessionId while keeping the same verified signed cookie
    // still hits 429 SESSION immediately (never keys rate limits on body fields)
    const r2 = await copilotPost(
      makeSignedAiRequest({
        path: '/api/copilot',
        body: { alertId: 'ALT-APP-003', question: 'Tóm tắt vụ việc?', sessionId: 'spoofed-body-2' },
        sessionId: verifiedSession,
        clientIp: '198.51.100.10',
      })
    );
    expect(r2.status).toBe(429);
    expect(r2.headers.get('Retry-After')).toBeTruthy();
    const j2 = await r2.json();
    expect(j2.limitScope).toBe('SESSION');
    // Confirm Redis keys NEVER used any spoofed session IDs
    expect(upstash.incrementedKeys.some((k) => k.includes('spoofed'))).toBe(false);
    expect(upstash.incrementedKeys.some((k) => k.includes(verifiedSession))).toBe(true);
  });

  it('enforces OCR-specific lower limit on /api/merchant/vision and sandbox limit on /api/sandbox with Retry-After headers', async () => {
    const upstash = new StatefulUpstashMock();
    process.env.UPSTASH_REDIS_REST_URL = 'https://mock-upstash.upstash.io';
    process.env.UPSTASH_REDIS_REST_TOKEN = 'mock-upstash-token';
    process.env.AEGIS_REQUIRE_DISTRIBUTED_RATE_LIMIT = 'true';
    process.env.TRUST_PROXY_HEADERS = 'true';
    process.env.AEGIS_E2E_DISABLE_EXTERNAL_AI = 'true';
    process.env.AI_RATE_LIMIT_PER_MIN = '10';
    process.env.AI_OCR_RATE_LIMIT_PER_MIN = '1';
    process.env.AI_SANDBOX_RATE_LIMIT_PER_MIN = '1';
    process.env.AI_IP_BURST_LIMIT_PER_MIN = '20';

    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = typeof input === 'string' ? input : input.toString();
      return Promise.resolve(upstash.handleRequest(url, init));
    });

    const sid = `ocr-sbx-${Date.now()}`;
    const mv1 = await merchantVisionPost(
      makeSignedAiRequest({
        path: '/api/merchant/vision',
        body: { imageDataUrl: VALID_32X32_PNG_DATA_URL },
        sessionId: sid,
        clientIp: '198.51.100.22',
      })
    );
    expect(mv1.status).toBe(200);
    const mv1Json = await mv1.json();
    expect(mv1Json.verification?.aiMetadata?.executionPath).toBe('AI_UNAVAILABLE');

    const mv2 = await merchantVisionPost(
      makeSignedAiRequest({
        path: '/api/merchant/vision',
        body: { imageDataUrl: VALID_32X32_PNG_DATA_URL },
        sessionId: sid,
        clientIp: '198.51.100.22',
      })
    );
    expect(mv2.status).toBe(429);
    expect(Number(mv2.headers.get('Retry-After'))).toBeGreaterThan(0);
    expect((await mv2.json()).limitScope).toBe('SESSION');

    const sb1 = await sandboxPost(
      makeSignedAiRequest({
        path: '/api/sandbox',
        body: { rawTranscript: 'Kịch bản mô phỏng chuyển 15 triệu', amountVnd: 15000000 },
        sessionId: sid,
        clientIp: '198.51.100.22',
      })
    );
    expect(sb1.status).toBe(200);

    const sb2 = await sandboxPost(
      makeSignedAiRequest({
        path: '/api/sandbox',
        body: { rawTranscript: 'Kịch bản mô phỏng lần 2', amountVnd: 15000000 },
        sessionId: sid,
        clientIp: '198.51.100.22',
      })
    );
    expect(sb2.status).toBe(429);
    expect(Number(sb2.headers.get('Retry-After'))).toBeGreaterThan(0);
    expect((await sb2.json()).limitScope).toBe('SESSION');
  });

  it('enforces distributed global Gemini quota via Upstash Redis and fails closed (503) on Redis outage or missing credentials in strict mode', async () => {
    const upstash = new StatefulUpstashMock();
    process.env.UPSTASH_REDIS_REST_URL = 'https://mock-upstash.upstash.io';
    process.env.UPSTASH_REDIS_REST_TOKEN = 'mock-upstash-token';
    process.env.AEGIS_REQUIRE_DISTRIBUTED_RATE_LIMIT = 'true';
    process.env.GEMINI_API_KEY = 'AIzaSyTestGlobalQuotaKey123456';
    process.env.GEMINI_QUOTA_SCOPE_ID = 'project-contest-test';
    process.env.GEMINI_GLOBAL_RPM_LIMIT = '1';
    process.env.AEGIS_E2E_DISABLE_EXTERNAL_AI = 'false';

    const { alert, forensics } = buildSampleForensics();
    const validBriefJson = JSON.stringify({
      classification: forensics.fallbackReport.classification,
      confidenceScore: 92,
      executiveSummaryVi: 'Kết quả AI trong giới hạn global quota.',
      keyFindingsVi: [`Bằng chứng ${forensics.validEvidenceIds[0]}`],
      citedEvidenceIds: forensics.validEvidenceIds.slice(0, 2),
      userShieldWarningVi: 'Cảnh báo mô phỏng.',
      recommendedActions: forensics.fallbackReport.recommendedActions,
    });

    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.startsWith('https://mock-upstash.upstash.io')) {
        return Promise.resolve(upstash.handleRequest(url, init));
      }
      return Promise.resolve(
        new Response(
          JSON.stringify({
            candidates: [{ content: { parts: [{ text: validBriefJson }] } }],
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        )
      );
    });

    // Call 1 consumes global RPM=1 -> PRIMARY_MODEL
    const first = await runGeminiInvestigationWithFallback({
      alert,
      forensics,
      evidenceTranscript: 'Global quota call 1',
    });
    expect(first.aiMetadata?.executionPath).toBe('PRIMARY_MODEL');

    // Call 2 hits global distributed quota limit -> deterministic fallback with QUOTA_EXCEEDED
    const second = await runGeminiInvestigationWithFallback({
      alert,
      forensics,
      evidenceTranscript: 'Global quota call 2',
    });
    expect(second.aiMetadata?.executionPath).toBe('DETERMINISTIC_FALLBACK');
    expect(second.aiMetadata?.fallbackReason).toBe('QUOTA_EXCEEDED');

    // Upstash outage in strict mode -> HTTP 503 DISTRIBUTED_RATE_LIMIT_UNAVAILABLE (never silent memory fallback)
    vi.restoreAllMocks();
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('Redis unavailable', { status: 500 }));
    const outageRes = await investigatePost(
      makeSignedAiRequest({
        path: '/api/investigate',
        body: { alertId: 'ALT-APP-003' },
        sessionId: `outage-sid-${Date.now()}`,
        clientIp: '198.51.100.33',
      })
    );
    expect(outageRes.status).toBe(503);
    expect(outageRes.headers.get('Retry-After')).toBeTruthy();
    expect((await outageRes.json()).code).toBe('DISTRIBUTED_RATE_LIMIT_UNAVAILABLE');

    // Missing Upstash credentials in strict mode -> HTTP 503 (never falls back to unrestricted memory)
    delete process.env.UPSTASH_REDIS_REST_URL;
    delete process.env.UPSTASH_REDIS_REST_TOKEN;
    const unconfiguredRes = await investigatePost(
      makeSignedAiRequest({
        path: '/api/investigate',
        body: { alertId: 'ALT-APP-003' },
        sessionId: `unconf-sid-${Date.now()}`,
        clientIp: '198.51.100.34',
      })
    );
    expect(unconfiguredRes.status).toBe(503);
    expect((await unconfiguredRes.json()).code).toBe('DISTRIBUTED_RATE_LIMIT_UNAVAILABLE');
  });
});
