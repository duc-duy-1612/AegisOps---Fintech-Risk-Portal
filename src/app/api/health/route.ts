import { timingSafeEqual } from 'node:crypto';
import { NextRequest, NextResponse } from 'next/server';
import {
  enforceDistributedRouteRateLimit,
  pingDistributedRateLimiter,
} from '@/infrastructure/distributed-rate-limiter';
import {
  evaluateGeminiFallbackReadiness,
  getGeminiOperationalMetrics,
  hasConfiguredGeminiKey,
  isStrictGeminiQuotaScopeRequired,
  resolveGeminiModelConfig,
  resolveGlobalGeminiQuotaConfig,
} from '@/infrastructure/gemini-resilience';
import { getWorkspacePersistenceAdapter } from '@/infrastructure/persistence-adapter';
import { getPiiHmacStatus } from '@/infrastructure/privacy-hasher';
import {
  getSessionSecretStatus,
  isDemoPersonaSwitchEnabled,
  isProductionStrictDemoGuardViolated,
  isStrictSecretsModeEnabled,
  validateStrictSecretsConfiguration,
} from '@/infrastructure/session-auth';

export const dynamic = 'force-dynamic';

export type DeploymentReadinessTier =
  | 'PRODUCTION_SHARED_INFRA_READY'
  | 'LOCAL_DEV_MEMORY_FALLBACK'
  | 'NOT_READY';

const FORBIDDEN_DIAGNOSTICS_QUERY_PARAMS = [
  'token',
  'diagnostics_token',
  'diagnosticsToken',
  'x-aegis-diagnostics-token',
  'secret',
  'key',
] as const;

const hasDiagnosticsTokenInQueryParams = (req?: NextRequest): boolean => {
  if (!req?.nextUrl?.searchParams) return false;
  return FORBIDDEN_DIAGNOSTICS_QUERY_PARAMS.some((param) => req.nextUrl.searchParams.has(param));
};

/**
 * Strictly authorizes internal diagnostics (`GET /api/health?diagnostics=internal`).
 * - Requires dedicated `AEGIS_DIAGNOSTICS_SECRET` (>= 32 chars) via `x-aegis-diagnostics-token` header.
 * - Never falls back to or accepts `AEGIS_SESSION_SECRET` or `AEGIS_ADMIN_RESET_SECRET` (enforces secret separation).
 * - Never accepts simulated demo personas (`END_USER`, `L1_MAKER`, or simulated `L2_CHECKER` demo sessions).
 * - Never accepts diagnostics tokens passed in URL query parameters.
 */
const isAuthorizedForInternalDiagnostics = (req?: NextRequest): boolean => {
  if (!req) return false;
  if (hasDiagnosticsTokenInQueryParams(req)) return false;

  const diagHeaderToken = req.headers.get('x-aegis-diagnostics-token')?.trim();
  const configuredDiagSecret = (process.env.AEGIS_DIAGNOSTICS_SECRET ?? '').trim();

  if (!diagHeaderToken || configuredDiagSecret.length < 32) {
    return false;
  }

  // Enforce strict cryptographic domain separation: reject if diagnostics secret reuses session or admin-reset secret
  const sessionSecret = (process.env.AEGIS_SESSION_SECRET ?? '').trim();
  const adminResetSecret = (process.env.AEGIS_ADMIN_RESET_SECRET ?? '').trim();
  if (
    (sessionSecret && configuredDiagSecret === sessionSecret) ||
    (adminResetSecret && configuredDiagSecret === adminResetSecret)
  ) {
    return false;
  }

  const aBuf = Buffer.from(diagHeaderToken, 'utf8');
  const bBuf = Buffer.from(configuredDiagSecret, 'utf8');
  return aBuf.length === bBuf.length && timingSafeEqual(aBuf, bBuf);
};

export function GET(): Promise<NextResponse>;
export function GET(req: NextRequest): Promise<NextResponse>;
export async function GET(req?: NextRequest): Promise<NextResponse> {
  const probe = req?.nextUrl?.searchParams.get('probe');
  if (probe === 'live') {
    return NextResponse.json({
      status: 'ok',
      probe: 'liveness',
      service: 'AegisOps Fintech Defense Workspace',
      timestamp: new Date().toISOString(),
    });
  }

  const wantsInternalDiagnostics = req?.nextUrl?.searchParams.get('diagnostics') === 'internal';
  if (wantsInternalDiagnostics) {
    if (req) {
      const rl = await enforceDistributedRouteRateLimit(req, 'health-diagnostics', 15);
      if (!rl.allowed) {
        const isMisconfigured = rl.modeUsed === 'MISCONFIGURED_FAIL_CLOSED' || rl.degraded;
        return NextResponse.json(
          {
            code: isMisconfigured
              ? 'RATE_LIMIT_BACKEND_UNAVAILABLE'
              : 'DIAGNOSTICS_RATE_LIMIT_EXCEEDED',
            errorVi: isMisconfigured
              ? 'Máy chủ Fail-Closed (HTTP 503): Hạ tầng giới hạn tốc độ chẩn đoán chưa sẵn sàng.'
              : 'Quá giới hạn truy vấn chẩn đoán nội bộ (HTTP 429). Vui lòng thử lại sau.',
          },
          { status: isMisconfigured ? 503 : 429 }
        );
      }
    }

    if (!isAuthorizedForInternalDiagnostics(req)) {
      return NextResponse.json(
        {
          code: 'FORBIDDEN_INTERNAL_DIAGNOSTICS',
          errorVi:
            'Từ chối truy cập (HTTP 403): Chẩn đoán nội bộ yêu cầu header x-aegis-diagnostics-token hợp lệ khớp với AEGIS_DIAGNOSTICS_SECRET chuyên biệt (>= 32 ký tự).',
        },
        { status: 403 }
      );
    }
  }

  const strictSecrets = validateStrictSecretsConfiguration();
  const secretStatus = getSessionSecretStatus();
  const piiStatus = getPiiHmacStatus();
  const [persistencePing, rateLimiterPing] = await Promise.all([
    getWorkspacePersistenceAdapter().ping(),
    pingDistributedRateLimiter(),
  ]);
  const aiMetrics = getGeminiOperationalMetrics();
  const modelConfig = resolveGeminiModelConfig();
  const fallbackReadiness = evaluateGeminiFallbackReadiness();
  const globalQuotaConfig = resolveGlobalGeminiQuotaConfig();

  const requireStrictSecrets = isStrictSecretsModeEnabled();
  const requireSharedPersistence =
    process.env.AEGIS_REQUIRE_SHARED_PERSISTENCE === 'true' ||
    process.env.AEGIS_PRODUCTION_STRICT_READINESS === 'true';
  const requireDistributedRateLimit =
    process.env.AEGIS_REQUIRE_DISTRIBUTED_RATE_LIMIT === 'true' ||
    process.env.AEGIS_PRODUCTION_STRICT_READINESS === 'true';
  const requireStrictQuotaScope = isStrictGeminiQuotaScopeRequired();

  const secretsReady =
    strictSecrets.ok &&
    (!requireStrictSecrets ||
      (secretStatus.mode === 'CONFIGURED_ENV' && piiStatus.mode === 'CONFIGURED_ENV'));

  // Memory fallback ('MEMORY') never satisfies required shared persistence in strict production mode
  const persistenceReady =
    persistencePing.ok &&
    persistencePing.mode !== 'MISCONFIGURED_FAIL_CLOSED' &&
    (!requireSharedPersistence || persistencePing.mode === 'POSTGRES');

  // Memory fallback ('MEMORY_SINGLE_INSTANCE') never satisfies required distributed rate limiting in strict production mode
  const rateLimiterReady =
    rateLimiterPing.mode !== 'MISCONFIGURED_FAIL_CLOSED' &&
    (requireDistributedRateLimit
      ? rateLimiterPing.ok && rateLimiterPing.mode === 'UPSTASH_REDIS'
      : true);

  const quotaScopeReady =
    aiMetrics.quotaScopeMode !== 'MISCONFIGURED_FAIL_CLOSED' &&
    (!requireStrictQuotaScope || aiMetrics.quotaScopeMode === 'CONFIGURED_PROJECT_SCOPE');

  const globalQuotaConfigReady =
    !globalQuotaConfig.hasMalformedConfig || (!requireDistributedRateLimit && !requireStrictQuotaScope);

  const fallbackModelReady = fallbackReadiness.fallbackReady;

  const demoPersonaGuardReady = !isProductionStrictDemoGuardViolated();

  const readinessOk =
    secretsReady &&
    persistenceReady &&
    rateLimiterReady &&
    quotaScopeReady &&
    globalQuotaConfigReady &&
    fallbackModelReady &&
    demoPersonaGuardReady;

  const isProductionSharedInfra =
    readinessOk &&
    persistencePing.mode === 'POSTGRES' &&
    rateLimiterPing.mode === 'UPSTASH_REDIS' &&
    secretStatus.mode === 'CONFIGURED_ENV' &&
    piiStatus.mode === 'CONFIGURED_ENV' &&
    (!hasConfiguredGeminiKey() || aiMetrics.quotaScopeMode === 'CONFIGURED_PROJECT_SCOPE');

  const deploymentReadinessTier: DeploymentReadinessTier = !readinessOk
    ? 'NOT_READY'
    : isProductionSharedInfra
      ? 'PRODUCTION_SHARED_INFRA_READY'
      : 'LOCAL_DEV_MEMORY_FALLBACK';

  // Public operational health payload: strictly redacted (no credential fingerprints, project scope IDs, secret modes, missing env names, or Redis keys)
  const publicPayload: Record<string, unknown> = {
    status: readinessOk
      ? aiMetrics.mode === 'AI_COOLDOWN_DEGRADED'
        ? 'degraded_ai'
        : 'ok'
      : 'not_ready',
    probe: 'readiness',
    service: 'AegisOps Fintech Defense Workspace',
    readinessOk,
    deploymentReadinessTier,
    aiEngineReady: aiMetrics.aiEngineReady,
    aiMode: aiMetrics.mode,
    aiCircuit: {
      state: aiMetrics.circuitState,
    },
    dependencies: {
      secretsReady,
      persistenceReady,
      rateLimiterReady,
      quotaScopeReady,
      globalQuotaConfigReady,
      fallbackModelReady,
      demoPersonaGuardReady,
    },
    primaryModel: modelConfig.primaryModel,
    fallbackModel: modelConfig.fallbackModel,
    fallbackSource: modelConfig.fallbackSource,
    timestamp: new Date().toISOString(),
  };

  if (wantsInternalDiagnostics) {
    publicPayload.internalDiagnostics = {
      deploymentReadinessTier,
      demoPersonaSwitchEnabled: isDemoPersonaSwitchEnabled(),
      demoPersonaGuardReady,
      aiModelConfig: {
        primaryModel: modelConfig.primaryModel,
        fallbackModel: modelConfig.fallbackModel,
        primarySource: modelConfig.primarySource,
        fallbackSource: modelConfig.fallbackSource,
        usingLegacyFallbackDefault: fallbackReadiness.usingLegacyFallbackDefault,
        fallbackModelReady,
        ...(fallbackReadiness.warningCode
          ? { fallbackWarningCode: fallbackReadiness.warningCode }
          : {}),
        isLegacyAutoRoutingModel: modelConfig.isLegacyAutoRoutingModel,
      },
      sessionSecretMode: secretStatus.mode,
      piiHmacMode: piiStatus.mode,
      strictSecretsMissing: strictSecrets.ok ? [] : strictSecrets.missingKeys,
      persistence: persistencePing,
      rateLimiter: rateLimiterPing,
      aiQuotaScope: {
        quotaScopeId: aiMetrics.quotaScopeId,
        quotaScopeMode: aiMetrics.quotaScopeMode,
        quotaScopeReady,
        globalQuotaConfigReady,
        globalRpmMax: globalQuotaConfig.globalRpmMax,
        globalOcrRpmMax: globalQuotaConfig.globalOcrRpmMax,
      },
      aiConcurrency: {
        concurrencyScope: aiMetrics.concurrencyScope,
        perInstanceMaxConcurrentGemini: aiMetrics.perInstanceMaxConcurrentGemini,
        perInstanceMaxConcurrentVisionOcr: aiMetrics.perInstanceMaxConcurrentVisionOcr,
        inFlightCount: aiMetrics.inFlightCount,
        inFlightVisionOcrCount: aiMetrics.inFlightVisionOcrCount,
      },
      aiCircuitDetail: {
        state: aiMetrics.circuitState,
        latched: aiMetrics.latched,
        cooldownRemainingMs: aiMetrics.cooldownRemainingMs,
        recoveryDeadlineIso: aiMetrics.recoveryDeadlineMs
          ? new Date(aiMetrics.recoveryDeadlineMs).toISOString()
          : null,
        deadlineSource: aiMetrics.deadlineSource,
        deadlineDisclaimer:
          aiMetrics.deadlineSource === 'APPLICATION_CONSERVATIVE_COOLDOWN'
            ? 'Application-configured conservative probe cooldown (not a provider-confirmed quota restoration timestamp).'
            : undefined,
        spendLimitStrikeCount: aiMetrics.spendLimitStrikeCount,
        lastErrorCategory: aiMetrics.lastErrorCategory,
        credentialFingerprint: aiMetrics.credentialFingerprint,
        quotaScopeId: aiMetrics.quotaScopeId,
        quotaScopeMode: aiMetrics.quotaScopeMode,
      },
    };
  }

  return NextResponse.json(publicPayload, { status: readinessOk ? 200 : 503 });
}
