import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { NextRequest } from 'next/server';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { GET as healthGet } from '@/app/api/health/route';
import { POST as investigatePost } from '@/app/api/investigate/route';
import { runDeterministicForensicsSuite } from '@/domain/forensics-analyzers';
import {
  askGeminiCopilotOnCase,
  extractMerchantBillWithGeminiVision,
  extractSandboxEntitiesWithGeminiVision,
  runGeminiInvestigationWithFallback,
} from '@/infrastructure/gemini-agent';
import {
  DEFAULT_GEMINI_PRIMARY_MODEL,
  executeResilientGeminiGenerateContent,
  getGeminiCredentialFingerprint,
  getGeminiOperationalMetrics,
  hasConfiguredGeminiKey,
  isE2eExternalAiDisabled,
  resetGeminiResilienceForTest,
  resolveGeminiModelConfig,
} from '@/infrastructure/gemini-resilience';
import {
  SEED_ACCOUNTS,
  SEED_ALERTS,
  SEED_API_EVENTS,
  SEED_AUTH_LOGS,
  SEED_DEVICES,
  SEED_EVIDENCES,
  SEED_TRANSACTIONS,
} from '@/infrastructure/seed-scenarios';
import { resetRateBucketsForTest } from '@/infrastructure/security-guard';
import {
  SESSION_COOKIE_NAME,
  createSignedSessionToken,
} from '@/infrastructure/session-auth';
import { resetSessionDelta } from '@/infrastructure/workspace-store';

describe('CR-2.2 E2E External Gemini Isolation & Deterministic Regression', () => {
  const savedEnv = { ...process.env };

  beforeEach(() => {
    resetRateBucketsForTest();
    resetGeminiResilienceForTest();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    for (const key of Object.keys(process.env)) {
      if (!(key in savedEnv)) {
        delete process.env[key];
      }
    }
    Object.assign(process.env, savedEnv);
    resetGeminiResilienceForTest();
  });

  it('blocks server-side Gemini transport locally before any fetch when AEGIS_E2E_DISABLE_EXTERNAL_AI=true, even if a real-looking GEMINI_API_KEY is present', async () => {
    process.env.AEGIS_E2E_DISABLE_EXTERNAL_AI = 'true';
    process.env.GEMINI_API_KEY = 'AIzaSyCr22SyntheticKeyShouldNeverBeSent_123456';
    delete process.env.VERCEL_ENV;
    delete process.env.AEGIS_PRODUCTION_STRICT_READINESS;

    expect(isE2eExternalAiDisabled()).toBe(true);
    expect(hasConfiguredGeminiKey()).toBe(false);
    expect(getGeminiCredentialFingerprint()).toBe('cred_e2e_isolated');

    const fetchSpy = vi.spyOn(globalThis, 'fetch');

    const res = await executeResilientGeminiGenerateContent({
      model: DEFAULT_GEMINI_PRIMARY_MODEL,
      parts: [{ text: 'E2E isolation probe' }],
      jsonMode: true,
      operationKind: 'INVESTIGATION',
    });

    expect(fetchSpy).not.toHaveBeenCalled();
    expect(res.ok).toBe(false);
    expect(res.text).toBeNull();
    expect(res.e2eIsolated).toBe(true);
    expect(res.category).toBe('E2E_ISOLATED_LOCAL_ONLY');
    expect(res.attempts).toBe(0);
    expect(res.circuitTripped).toBeUndefined();

    const metrics = getGeminiOperationalMetrics();
    expect(metrics.mode).toBe('AI_UNCONFIGURED');
    expect(metrics.aiEngineReady).toBe(false);
    expect(metrics.circuitState).toBe('CLOSED');
    expect(metrics.totalRequests).toBe(0);
    expect(metrics.totalFallbacks).toBeGreaterThanOrEqual(1);
  });

  it('isolates all four Gemini agent call sites (Investigation, Copilot, Sandbox, Merchant Vision) with zero outbound fetch calls and valid deterministic contracts', async () => {
    process.env.AEGIS_E2E_DISABLE_EXTERNAL_AI = 'true';
    delete process.env.GEMINI_API_KEY;
    delete process.env.VERCEL_ENV;
    delete process.env.AEGIS_PRODUCTION_STRICT_READINESS;

    const fetchSpy = vi.spyOn(globalThis, 'fetch');
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

    const invReport = await runGeminiInvestigationWithFallback({
      alert,
      forensics,
      evidenceTranscript: 'E2E isolated investigation test',
    });
    expect(invReport.modelUsed).toBe('deterministic-forensics-engine-v2');
    expect(invReport.deterministicRiskScore).toBe(forensics.deterministicRiskScore);
    expect(invReport.classification).toBe(forensics.fallbackReport.classification);

    const copilotReply = await askGeminiCopilotOnCase({
      question: 'Tóm tắt rủi ro chính của vụ án này?',
      alert,
      forensics,
    });
    expect(copilotReply.modelUsed).toBe('deterministic-copilot-v1');
    expect(copilotReply.citedEvidenceIds.length).toBeGreaterThan(0);

    const sandboxEntities = await extractSandboxEntitiesWithGeminiVision(
      'Chuyen gap 18.000.000 VND vao STK 1903999888777'
    );
    expect(sandboxEntities.recipientAccountNumber).toBe('1903999888777');
    expect(sandboxEntities.amountVnd).toBe(18_000_000);

    const visionRes = await extractMerchantBillWithGeminiVision({
      mimeType: 'image/png',
      base64Data:
        'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=',
    });
    expect(visionRes.outcome).toBe('AI_UNAVAILABLE');
    expect(visionRes.extracted).toBeNull();

    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('cannot accidentally activate in production or strict production readiness mode, and preserves non-E2E circuit-breaker & fallback behavior', async () => {
    process.env.AEGIS_E2E_DISABLE_EXTERNAL_AI = 'true';
    process.env.GEMINI_API_KEY = 'AIzaSyCr22ProdSafetyTestKey_0123456789';

    // 1. VERCEL_ENV=production disables E2E isolation guard
    process.env.VERCEL_ENV = 'production';
    delete process.env.AEGIS_PRODUCTION_STRICT_READINESS;
    expect(isE2eExternalAiDisabled()).toBe(false);
    expect(hasConfiguredGeminiKey()).toBe(true);

    // 2. AEGIS_PRODUCTION_STRICT_READINESS=true disables E2E isolation guard
    delete process.env.VERCEL_ENV;
    process.env.AEGIS_PRODUCTION_STRICT_READINESS = 'true';
    expect(isE2eExternalAiDisabled()).toBe(false);

    // 3. Normal non-E2E mode preserves resolveGeminiModelConfig and 429 RPD circuit breaker + deterministic fallback
    delete process.env.AEGIS_E2E_DISABLE_EXTERNAL_AI;
    delete process.env.AEGIS_PRODUCTION_STRICT_READINESS;
    delete process.env.GEMINI_PRIMARY_MODEL;
    delete process.env.GEMINI_MODEL;

    expect(isE2eExternalAiDisabled()).toBe(false);
    expect(resolveGeminiModelConfig().primaryModel).toBe(DEFAULT_GEMINI_PRIMARY_MODEL);

    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      new Response('{"error":{"code":429,"message":"Quota exceeded requests_per_day"}}', {
        status: 429,
      })
    );
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

    const fallbackReport = await runGeminiInvestigationWithFallback({
      alert,
      forensics,
      evidenceTranscript: 'Non-E2E 429 fallback test',
    });
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    expect(fallbackReport.modelUsed).toBe('deterministic-forensics-engine-v2');
    expect(getGeminiOperationalMetrics().circuitState).toBe('OPEN');
  });

  it('exercises real /api/investigate and /api/health routes in E2E mode with zero external network transmission', async () => {
    process.env.AEGIS_E2E_DISABLE_EXTERNAL_AI = 'true';
    process.env.GEMINI_API_KEY = 'AIzaSyCr22RouteIsolationKey_0123456789';
    delete process.env.VERCEL_ENV;
    delete process.env.AEGIS_PRODUCTION_STRICT_READINESS;

    const fetchSpy = vi.spyOn(globalThis, 'fetch');
    const sessionId = `cr22-route-${Date.now()}`;
    resetSessionDelta(sessionId);

    const token = createSignedSessionToken({
      sessionId,
      role: 'L2_CHECKER',
      principalId: 'checker-cr22',
    });
    const req = new NextRequest('http://localhost:3000/api/investigate', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        host: 'localhost:3000',
        origin: 'http://localhost:3000',
        'sec-fetch-site': 'same-origin',
        'x-workspace-session': sessionId,
        cookie: `${SESSION_COOKIE_NAME}=${token}`,
      },
      body: JSON.stringify({ alertId: 'ALT-APP-003' }),
    });

    const invRes = await investigatePost(req);
    expect(invRes.status).toBe(200);
    const invJson = await invRes.json();
    expect(invJson.report.modelUsed).toBe('deterministic-forensics-engine-v2');
    expect(invJson.forensics.deterministicRiskScore).toBe(95);
    expect(fetchSpy).not.toHaveBeenCalled();

    const healthRes = await healthGet(new NextRequest('http://localhost:3000/api/health'));
    expect(healthRes.status).toBe(200);
    const healthJson = await healthRes.json();
    expect(healthJson.status).toBe('ok');
    expect(healthJson.aiMode).toBe('AI_UNCONFIGURED');
    expect(healthJson.aiEngineReady).toBe(false);
    expect(healthJson.aiCircuit.state).toBe('CLOSED');
  });

  it('configures Playwright webServer to launch a dedicated isolated server with AEGIS_E2E_DISABLE_EXTERNAL_AI=true', () => {
    const playwrightCfg = readFileSync(join(process.cwd(), 'playwright.config.ts'), 'utf8');
    expect(playwrightCfg).toContain('reuseExistingServer: false');
    expect(playwrightCfg).toContain("AEGIS_E2E_DISABLE_EXTERNAL_AI: 'true'");
    expect(playwrightCfg).toContain("GEMINI_API_KEY: ''");
  });
});
