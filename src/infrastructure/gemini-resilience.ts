/**
 * Wave 4.1.4 & 4.1.3 Gemini Project-Level Quota Identity, Atomic Lua Reservation & Circuit Breaker Resilience.
 *
 * Key Guarantees:
 * 1. Separated Quota Project Identity (`proj_<24-hex>`) vs Credential Identity (`cred_<24-hex>`):
 *    - Project-level quotas (RPM, OCR RPM) and project/model circuits (`SPEND_LIMIT_EXHAUSTED`,
 *      `RPD_EXHAUSTED`, `UNKNOWN_RATE_LIMIT`, `RATE_LIMIT_RPM`/`TPM`, `TRANSIENT`) are keyed by
 *      `quotaScopeId` derived from `GEMINI_QUOTA_SCOPE_ID` (never derived from `GEMINI_API_KEY`).
 *    - Credential-specific authentication failures (`INVALID_API_KEY`) are keyed by `credFp` (`cred_<24-hex>`).
 *    - Rotating `GEMINI_API_KEY` within the same Google project purges only the retired credential's
 *      `INVALID_API_KEY` latch while preserving project-level quota counters and project circuits.
 *    - In strict production mode, missing `GEMINI_QUOTA_SCOPE_ID` fails closed (`MISCONFIGURED_FAIL_CLOSED`).
 * 2. Atomic Redis Lua (`EVAL`) Check-and-Reserve (`ATOMIC_CIRCUIT_GATE_AND_QUOTA_RESERVE_LUA`):
 *    - Eliminates the Phase-1-to-Phase-2 check-to-increment race in Redis by reading all 6 scoped
 *      circuit keys and checking/incrementing the trailing 60s weighted sliding-window RPM & OCR RPM
 *      counters inside a single atomic Redis Lua execution.
 *    - Rejected requests (due to open circuit, RPM limit, or OCR limit) never increment counters.
 *    - Residual race window is strictly bounded to already-dispatched in-flight HTTPS requests
 *      to Google Gemini (`<= timeoutMs`), which cannot be recalled after leaving the network socket;
 *      pre-dispatch and pre-retry checks abort immediately if a circuit opens.
 * 3. Atomic Monotonic Circuit Persistence (`ATOMIC_MONOTONIC_CIRCUIT_SET_LUA`):
 *    - Prevents `GET`-then-`SET` race conditions on the same Redis circuit key; a shorter deadline
 *      can never overwrite a latched or longer active deadline.
 * 4. Per-Instance Concurrency Semaphores vs Distributed Rate Limits:
 *    - `PER_INSTANCE_MAX_CONCURRENT_GEMINI = 4` and `PER_INSTANCE_MAX_CONCURRENT_VISION_OCR = 2`
 *      bound process-local in-flight requests per Node.js instance (`PER_INSTANCE_PROCESS_LOCAL`),
 *      while global cross-instance request rates are bounded by Redis sliding-window RPM/OCR quotas.
 * 5. Spend-Limit Cooldown Semantics (`SPEND_LIMIT_EXHAUSTED`):
 *    - Explicitly distinguishes `APPLICATION_CONSERVATIVE_COOLDOWN` (default 15m configurable probe interval)
 *      from `PROVIDER_RETRY_AFTER` and `PACIFIC_MIDNIGHT_CALCULATION`.
 *    - Tracks consecutive spend-limit strikes (`strikeCount`) across cooldown expirations and applies
 *      progressive exponential backoff (`15m -> 30m -> 60m -> ...` up to `4h` cap).
 */
import { createHash, timingSafeEqual } from 'node:crypto';
import { getUpstashConfig, type UpstashCommandEntry } from './distributed-rate-limiter';
import { generateRequestTraceId, logStructuredEvent, redactSensitiveMetadata } from './observability';

export type GeminiErrorCategory =
  | 'RATE_LIMIT_RPM'
  | 'RATE_LIMIT_TPM'
  | 'RPD_EXHAUSTED'
  | 'SPEND_LIMIT_EXHAUSTED'
  | 'INVALID_API_KEY'
  | 'UPSTREAM_OVERLOADED'
  | 'TIMEOUT'
  | 'UNKNOWN_RATE_LIMIT'
  | 'UNSUPPORTED_MODEL'
  | 'E2E_ISOLATED_LOCAL_ONLY'
  | 'OTHER_ERROR';

export type GeminiOperationalMode = 'AI_LIVE' | 'AI_COOLDOWN_DEGRADED' | 'AI_UNCONFIGURED';
export type GeminiOperationKind = 'INVESTIGATION' | 'COPILOT' | 'VISION_OCR';
export type GeminiOperationScope = 'TEXT' | 'VISION_OCR';

export type GeminiQuotaScopeMode =
  | 'CONFIGURED_PROJECT_SCOPE'
  | 'DEV_DEFAULT_FALLBACK'
  | 'MISCONFIGURED_FAIL_CLOSED';

export interface GeminiQuotaScopeStatus {
  scopeId: string | null;
  mode: GeminiQuotaScopeMode;
}

export type GeminiConcurrencyScope = 'PER_INSTANCE_PROCESS_LOCAL';

export type CircuitDeadlineSource =
  | 'PROVIDER_RETRY_AFTER'
  | 'PACIFIC_MIDNIGHT_CALCULATION'
  | 'APPLICATION_CONSERVATIVE_COOLDOWN'
  | 'CREDENTIAL_LATCH';

export interface CircuitConstraintEnvelope {
  category: GeminiErrorCategory;
  credentialFingerprint: string;
  quotaScopeId: string;
  model: string;
  opScope: GeminiOperationScope | 'GLOBAL';
  openedAtMs: number;
  deadlineMs: number | null;
  latched: boolean;
  deadlineSource: CircuitDeadlineSource;
  strikeCount: number;
  sanitizedReason: string;
  correlationId: string;
}

export interface GeminiRestExecutionResult {
  text: string | null;
  ok: boolean;
  category?: GeminiErrorCategory;
  httpStatus?: number;
  circuitTripped?: boolean;
  deduplicated?: boolean;
  distributedQuotaTripped?: boolean;
  failClosedRedisError?: boolean;
  failClosedQuotaScopeError?: boolean;
  e2eIsolated?: boolean;
  recoveryDeadlineMs?: number | null;
  deadlineSource?: CircuitDeadlineSource | null;
  latched?: boolean;
  attempts: number;
}

export interface ProviderRetryGuidance {
  hasValidGuidance: boolean;
  retryDelayMs: number;
}

const GEMINI_BASE_URL = 'https://generativelanguage.googleapis.com/v1beta/models';

/**
 * Authoritative Gemini Developer API model defaults (CR-2.1):
 * - `gemini-2.5-flash` is deprecated and auto-routes to `gemini-3.5-flash-lite` starting December 1, 2026.
 * - Default primary explicitly targets `gemini-3.5-flash-lite`; secondary fallback targets `gemini-2.5-flash-lite`
 *   (no announced shutdown date as of Nov 22, 2026).
 */
export const DEFAULT_GEMINI_PRIMARY_MODEL = 'gemini-3.5-flash-lite';
export const DEFAULT_GEMINI_FALLBACK_MODEL = 'gemini-2.5-flash-lite';

export interface ResolvedGeminiModelConfig {
  primaryModel: string;
  fallbackModel: string;
  primarySource: 'GEMINI_PRIMARY_MODEL' | 'GEMINI_MODEL' | 'DEFAULT';
  fallbackSource: 'GEMINI_FALLBACK_MODEL' | 'DEFAULT';
  isLegacyAutoRoutingModel: boolean;
}

export const resolveGeminiModelConfig = (
  env: NodeJS.ProcessEnv = process.env
): ResolvedGeminiModelConfig => {
  const explicitPrimary = env.GEMINI_PRIMARY_MODEL?.trim();
  const aliasPrimary = env.GEMINI_MODEL?.trim();
  const explicitFallback = env.GEMINI_FALLBACK_MODEL?.trim();

  const primaryModel = explicitPrimary || aliasPrimary || DEFAULT_GEMINI_PRIMARY_MODEL;
  const primarySource: ResolvedGeminiModelConfig['primarySource'] = explicitPrimary
    ? 'GEMINI_PRIMARY_MODEL'
    : aliasPrimary
      ? 'GEMINI_MODEL'
      : 'DEFAULT';

  const fallbackModel = explicitFallback || DEFAULT_GEMINI_FALLBACK_MODEL;
  const fallbackSource: ResolvedGeminiModelConfig['fallbackSource'] = explicitFallback
    ? 'GEMINI_FALLBACK_MODEL'
    : 'DEFAULT';

  return {
    primaryModel,
    fallbackModel,
    primarySource,
    fallbackSource,
    isLegacyAutoRoutingModel: primaryModel.toLowerCase() === 'gemini-2.5-flash',
  };
};

export const isGemini3FamilyModel = (model: string): boolean => {
  return /^gemini-3(?:\.|[-_]|$)/i.test((model || '').trim());
};

/**
 * Builds model-compatible `generationConfig` for Gemini Developer API `v1beta`:
 * - Gemini 3.x (`gemini-3.5-flash-lite`): omits unsupported custom `temperature` sampling override,
 *   uses `thinkingConfig: { thinkingLevel: 'minimal' }` for low-latency structured JSON / OCR, and raises
 *   `maxOutputTokens` to 2048 so thinking + JSON payload do not truncate.
 * - Gemini 2.x (`gemini-2.5-flash-lite`, etc.): preserves legacy `temperature: 0.15` & `maxOutputTokens: 1024`.
 */
export const buildGeminiGenerationConfig = (params: {
  model: string;
  jsonMode: boolean;
  operationKind?: GeminiOperationKind;
}): Record<string, unknown> => {
  if (isGemini3FamilyModel(params.model)) {
    return {
      maxOutputTokens: 2048,
      thinkingConfig: {
        thinkingLevel: 'minimal',
      },
      ...(params.jsonMode ? { responseMimeType: 'application/json' } : {}),
    };
  }
  return {
    temperature: 0.15,
    maxOutputTokens: 1024,
    ...(params.jsonMode ? { responseMimeType: 'application/json' } : {}),
  };
};

interface GeminiCandidatePart {
  text?: string;
  thought?: boolean;
}

/**
 * Extracts visible output text from Gemini `generateContent` candidates while filtering out
 * internal thinking parts (`part.thought === true`) emitted by Gemini 3.x reasoning models.
 */
export const extractPrimaryCandidateText = (data: {
  candidates?: Array<{ content?: { parts?: GeminiCandidatePart[] } }>;
}): string | null => {
  const parts = data.candidates?.[0]?.content?.parts;
  if (!Array.isArray(parts) || parts.length === 0) return null;

  const visibleParts = parts.filter(
    (p) => !p?.thought && typeof p?.text === 'string' && p.text.trim().length > 0
  );
  if (visibleParts.length > 0) {
    return visibleParts
      .map((p) => p.text!.trim())
      .join('\n')
      .trim();
  }
  return null;
};
/**
 * Per-instance (Node.js process-local) concurrency semaphores.
 * NOTE: These protect a single serverless instance from event-loop/socket saturation and base64 OCR memory spikes.
 * Global cross-instance request rates are bounded by the shared Redis Lua sliding-window RPM (`GEMINI_GLOBAL_RPM_LIMIT`)
 * and OCR RPM (`GEMINI_GLOBAL_OCR_RPM_LIMIT`) counters keyed by project quota scope (`quotaScopeId`).
 */
export const PER_INSTANCE_MAX_CONCURRENT_GEMINI = 4;
export const PER_INSTANCE_MAX_CONCURRENT_VISION_OCR = 2;
const MAX_CONCURRENT_GEMINI = PER_INSTANCE_MAX_CONCURRENT_GEMINI;
const MAX_CONCURRENT_VISION_OCR = PER_INSTANCE_MAX_CONCURRENT_VISION_OCR;
const FAILURE_THRESHOLD_TO_OPEN = 3;
const MAX_IN_REQUEST_RETRY_WAIT_MS = 4_000;

const DEFAULT_RPM_TPM_COOLDOWN_MS = 30_000;
const DEFAULT_TRANSIENT_OVERLOAD_COOLDOWN_MS = 25_000;
const DEFAULT_UNKNOWN_429_COOLDOWN_MS = 60_000;
/**
 * Application-configured conservative probe cooldown for `SPEND_LIMIT_EXHAUSTED` (default: 15 minutes).
 * IMPORTANT: This is an application-level conservative cooldown before sending a single recovery probe,
 * NOT a Google-guaranteed quota restoration timestamp. If the post-cooldown probe still receives
 * `SPEND_LIMIT_EXHAUSTED`, consecutive strikes escalate exponentially up to `MAX_SPEND_LIMIT_COOLDOWN_MS` (4h).
 */
const DEFAULT_SPEND_LIMIT_COOLDOWN_MS = 15 * 60_000;
const MAX_SPEND_LIMIT_COOLDOWN_MS = 4 * 3600_000;
const DEFAULT_RPD_RESET_SAFETY_MARGIN_MS = 60_000;
const LATCHED_CREDENTIAL_REDIS_TTL_MS = 24 * 3600_000;
const SLIDING_WINDOW_BUCKET_TTL_MS = 125_000;

const CATEGORY_SEVERITY_RANK: Readonly<Record<GeminiErrorCategory, number>> = {
  INVALID_API_KEY: 100,
  RPD_EXHAUSTED: 90,
  SPEND_LIMIT_EXHAUSTED: 85,
  UNKNOWN_RATE_LIMIT: 70,
  RATE_LIMIT_TPM: 60,
  RATE_LIMIT_RPM: 55,
  UPSTREAM_OVERLOADED: 45,
  TIMEOUT: 40,
  UNSUPPORTED_MODEL: 20,
  OTHER_ERROR: 10,
  E2E_ISOLATED_LOCAL_ONLY: 0,
};

/**
 * Atomic Redis Lua script executing circuit check AND weighted sliding-window quota reservation
 * in a single linearizable step on Redis (eliminating Phase-1-to-Phase-2 check-to-increment races).
 */
export const ATOMIC_CIRCUIT_GATE_AND_QUOTA_RESERVE_LUA = `
local c1 = redis.call('GET', KEYS[1])
local c2 = redis.call('GET', KEYS[2])
local c3 = redis.call('GET', KEYS[3])
local c4 = redis.call('GET', KEYS[4])
local c5 = redis.call('GET', KEYS[5])
local c6 = redis.call('GET', KEYS[6])
if c1 or c2 or c3 or c4 or c5 or c6 then
  return {'CIRCUIT_OPEN', c1 or '', c2 or '', c3 or '', c4 or '', c5 or '', c6 or ''}
end
local rpmMax = tonumber(ARGV[2])
local ocrMax = tonumber(ARGV[3])
local isOcr = ARGV[4] == '1'
local ttlMs = tonumber(ARGV[5])
local weightMillis = tonumber(ARGV[6])

local currRpm = tonumber(redis.call('GET', KEYS[7]) or '0')
local prevRpm = tonumber(redis.call('GET', KEYS[8]) or '0')
local nextRpm = currRpm + 1
local slidingRpm = nextRpm + math.ceil((prevRpm * weightMillis) / 1000)
if nextRpm > rpmMax or slidingRpm > rpmMax then
  return {'QUOTA_RPM_EXCEEDED', tostring(currRpm), tostring(slidingRpm)}
end

local nextOcr = 0
if isOcr then
  local currOcr = tonumber(redis.call('GET', KEYS[9]) or '0')
  local prevOcr = tonumber(redis.call('GET', KEYS[10]) or '0')
  nextOcr = currOcr + 1
  local slidingOcr = nextOcr + math.ceil((prevOcr * weightMillis) / 1000)
  if nextOcr > ocrMax or slidingOcr > ocrMax then
    return {'QUOTA_OCR_EXCEEDED', tostring(currOcr), tostring(slidingOcr)}
  end
end

local committedRpm = redis.call('INCR', KEYS[7])
redis.call('PEXPIRE', KEYS[7], ttlMs, 'NX')
local committedOcr = 0
if isOcr then
  committedOcr = redis.call('INCR', KEYS[9])
  redis.call('PEXPIRE', KEYS[9], ttlMs, 'NX')
end
return {'ALLOWED', tostring(committedRpm), tostring(committedOcr)}
`.trim();

/**
 * Atomic Redis Lua script for monotonic circuit persistence:
 * Never allows a shorter deadline or unlatched record to overwrite an active longer deadline or latched record.
 */
export const ATOMIC_MONOTONIC_CIRCUIT_SET_LUA = `
local existingRaw = redis.call('GET', KEYS[1])
local candJson = ARGV[1]
local candDeadline = tonumber(ARGV[2])
local candLatched = ARGV[3] == '1'
local ttlMs = tonumber(ARGV[4])
local nowMs = tonumber(ARGV[5])

if existingRaw then
  local isExistingLatched = string.find(existingRaw, '"latched":true', 1, true) ~= nil
  if isExistingLatched then
    return {'KEPT_EXISTING', existingRaw}
  end
  local _, _, existingDeadlineStr = string.find(existingRaw, '"deadlineMs":(%d+)')
  if existingDeadlineStr then
    local existingDeadline = tonumber(existingDeadlineStr)
    if existingDeadline and existingDeadline > nowMs and not candLatched and candDeadline >= 0 and existingDeadline >= candDeadline then
      return {'KEPT_EXISTING', existingRaw}
    end
  end
end

redis.call('SET', KEYS[1], candJson, 'PX', ttlMs)
return {'UPDATED', candJson}
`.trim();

/**
 * Explicit local/E2E server-side isolation guard (CR-2.2):
 * - Prevents all outbound Google Gemini API network requests during Playwright E2E / isolated local tests,
 *   even if `.env.local` contains a real `GEMINI_API_KEY`.
 * - Strictly refuses to activate in Vercel production (`VERCEL_ENV === 'production'`) or strict production
 *   readiness mode (`AEGIS_PRODUCTION_STRICT_READINESS === 'true'`).
 */
export const isE2eExternalAiDisabled = (env: NodeJS.ProcessEnv = process.env): boolean => {
  if (env.AEGIS_E2E_DISABLE_EXTERNAL_AI !== 'true') {
    return false;
  }
  if (env.VERCEL_ENV === 'production' || env.AEGIS_PRODUCTION_STRICT_READINESS === 'true') {
    return false;
  }
  return true;
};

export const hasConfiguredGeminiKey = (): boolean => {
  if (isE2eExternalAiDisabled()) {
    return false;
  }
  const apiKey = process.env.GEMINI_API_KEY?.trim();
  return Boolean(apiKey && apiKey !== 'your_gemini_api_key_here' && apiKey.length >= 16);
};

/**
 * Generates a non-reversible 96-bit (24-hex) domain-separated SHA-256 fingerprint of `GEMINI_API_KEY`.
 * - Never exposes raw API key characters, prefix, suffix, or length.
 * - Collision probability under Birthday bound is ~2^-48 at 2^24 distinct credentials.
 * - Automatically changes when `GEMINI_API_KEY` is rotated to a new value.
 */
export const getGeminiCredentialFingerprint = (rawKey?: string | null): string => {
  if (rawKey === undefined && isE2eExternalAiDisabled()) {
    return 'cred_e2e_isolated';
  }
  const key = (rawKey ?? process.env.GEMINI_API_KEY ?? '').trim();
  if (!key || key === 'your_gemini_api_key_here') {
    return 'cred_unconfigured';
  }
  const digest = createHash('sha256')
    .update(`aegis-gemini-cred-fp-v2:${key.length}:${key}`)
    .digest('hex')
    .slice(0, 24);
  return `cred_${digest}`;
};

export const isStrictGeminiQuotaScopeRequired = (): boolean => {
  if (process.env.AEGIS_REQUIRE_STRICT_GEMINI_QUOTA_SCOPE === 'true') {
    return true;
  }
  if (
    (process.env.AEGIS_PRODUCTION_STRICT_READINESS === 'true' ||
      process.env.AEGIS_REQUIRE_STRICT_SECRETS === 'true') &&
    hasConfiguredGeminiKey()
  ) {
    return true;
  }
  return false;
};

/**
 * Resolves the Google Project / Billing Quota Scope Identity (`proj_<24-hex>`).
 * - NEVER derived from `GEMINI_API_KEY`, because multiple API keys in the same Google project
 *   share the same project-level RPM, TPM, RPD, and spend-limit quotas.
 * - Derived from `GEMINI_QUOTA_SCOPE_ID` using a 96-bit domain-separated SHA-256 hash.
 * - In strict production mode, missing `GEMINI_QUOTA_SCOPE_ID` fails closed (`MISCONFIGURED_FAIL_CLOSED`)
 *   and never falls back to credential-scoped quota accounting.
 * - In local development mode, uses the explicit single-project default scope `'proj_dev_default_unscoped'`.
 */
export const getGeminiQuotaScopeStatus = (
  rawScopeOverride?: string | null
): GeminiQuotaScopeStatus => {
  const raw = (rawScopeOverride ?? process.env.GEMINI_QUOTA_SCOPE_ID ?? '').trim();
  if (
    raw &&
    raw.length >= 3 &&
    raw !== 'your_gemini_quota_scope_id_here' &&
    raw !== 'your_google_project_id_here'
  ) {
    const digest = createHash('sha256')
      .update(`aegis-gemini-proj-scope-v1:${raw.length}:${raw}`)
      .digest('hex')
      .slice(0, 24);
    return {
      scopeId: `proj_${digest}`,
      mode: 'CONFIGURED_PROJECT_SCOPE',
    };
  }

  if (isStrictGeminiQuotaScopeRequired()) {
    return {
      scopeId: null,
      mode: 'MISCONFIGURED_FAIL_CLOSED',
    };
  }

  return {
    scopeId: 'proj_dev_default_unscoped',
    mode: 'DEV_DEFAULT_FALLBACK',
  };
};

export const getGeminiQuotaScopeId = (rawScopeOverride?: string | null): string => {
  return getGeminiQuotaScopeStatus(rawScopeOverride).scopeId ?? 'proj_misconfigured_fail_closed';
};

const normalizeModelSlug = (model: string): string => {
  return (model || DEFAULT_GEMINI_PRIMARY_MODEL)
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]/g, '_');
};

const toOperationScope = (kind?: GeminiOperationKind): GeminiOperationScope => {
  return kind === 'VISION_OCR' ? 'VISION_OCR' : 'TEXT';
};

/**
 * Computes the UTC offset in milliseconds for `America/Los_Angeles` at a specific UTC instant
 * using `Intl.DateTimeFormat` (no hardcoded UTC-7 or UTC-8 offset; handles PST and PDT accurately).
 */
const getPacificWallClockParts = (utcMs: number): {
  year: number;
  month: number;
  day: number;
  hour: number;
  minute: number;
  second: number;
} => {
  const formatter = new Intl.DateTimeFormat('en-US', {
    timeZone: 'America/Los_Angeles',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hourCycle: 'h23',
  });
  const parts = formatter.formatToParts(new Date(utcMs));
  const map: Record<string, number> = {};
  for (const part of parts) {
    if (part.type !== 'literal') {
      map[part.type] = Number(part.value);
    }
  }
  return {
    year: map.year ?? 1970,
    month: map.month ?? 1,
    day: map.day ?? 1,
    hour: (map.hour ?? 0) === 24 ? 0 : (map.hour ?? 0),
    minute: map.minute ?? 0,
    second: map.second ?? 0,
  };
};

export const getPacificTimezoneOffsetMs = (utcMs: number): number => {
  const p = getPacificWallClockParts(utcMs);
  const pacificWallAsUtc = Date.UTC(p.year, p.month - 1, p.day, p.hour, p.minute, p.second);
  const truncatedUtc = Math.floor(utcMs / 1000) * 1000;
  return pacificWallAsUtc - truncatedUtc;
};

export const getPacificTimezoneOffsetHours = (utcMs: number): number => {
  return Math.round(getPacificTimezoneOffsetMs(utcMs) / 3_600_000);
};

/**
 * Calculates the next daily quota reset timestamp (midnight `00:00:00` in `America/Los_Angeles`
 * plus a configurable safety margin). Safe across both PST (UTC-8) and PDT (UTC-7) and DST transitions.
 */
export const computeNextPacificMidnightResetMs = (
  nowMs: number = Date.now(),
  safetyMarginOverrideMs?: number
): number => {
  const configuredMargin = Number(
    process.env.GEMINI_RPD_RESET_SAFETY_MARGIN_MS ?? DEFAULT_RPD_RESET_SAFETY_MARGIN_MS
  );
  const safetyMarginMs =
    safetyMarginOverrideMs !== undefined
      ? Math.max(0, Math.min(600_000, safetyMarginOverrideMs))
      : Number.isFinite(configuredMargin)
        ? Math.max(0, Math.min(600_000, Math.round(configuredMargin)))
        : DEFAULT_RPD_RESET_SAFETY_MARGIN_MS;

  const currentPacific = getPacificWallClockParts(nowMs);
  const nextMidnightWallAsUtc = Date.UTC(
    currentPacific.year,
    currentPacific.month - 1,
    currentPacific.day + 1,
    0,
    0,
    0,
    0
  );

  // Two-pass offset convergence to handle DST transitions accurately
  const offsetPass1 = getPacificTimezoneOffsetMs(nowMs);
  const estimateUtc1 = nextMidnightWallAsUtc - offsetPass1;
  const offsetPass2 = getPacificTimezoneOffsetMs(estimateUtc1);
  const exactMidnightUtcMs = nextMidnightWallAsUtc - offsetPass2;

  return exactMidnightUtcMs + safetyMarginMs;
};

const extractStructuredErrorTextAndDelay = (
  bodyText: string
): { combinedText: string; structuredRetryDelayMs: number; sanitizedNote: string } => {
  const raw = (bodyText ?? '').trim();
  if (!raw) {
    return { combinedText: '', structuredRetryDelayMs: 0, sanitizedNote: 'empty_provider_response' };
  }

  let combined = raw.toLowerCase();
  let structuredRetryDelayMs = 0;

  try {
    const parsed = JSON.parse(raw) as {
      error?: {
        message?: string;
        status?: string;
        details?: Array<Record<string, unknown>>;
      };
    };
    if (parsed && typeof parsed === 'object' && parsed.error) {
      const pieces: string[] = [
        parsed.error.message ?? '',
        parsed.error.status ?? '',
        JSON.stringify(parsed.error.details ?? []),
      ];
      combined = pieces.join(' ').toLowerCase();

      for (const detail of parsed.error.details ?? []) {
        const retryDelay = detail?.retryDelay;
        if (typeof retryDelay === 'string') {
          const m = retryDelay.trim().match(/^(\d+(?:\.\d+)?)s$/i);
          if (m && m[1]) {
            const sec = Number(m[1]);
            if (Number.isFinite(sec) && sec > 0) {
              structuredRetryDelayMs = Math.max(structuredRetryDelayMs, Math.round(sec * 1000));
            }
          }
        }
      }
    }
  } catch {
    // Fallback to raw text inspection when body is not valid JSON
  }

  if (structuredRetryDelayMs === 0) {
    const inlineMatch = raw.match(/retry\s*(?:in|after|delay[:\s"]*)\s*(\d+(?:\.\d+)?)\s*s/i);
    if (inlineMatch && inlineMatch[1]) {
      const sec = Number(inlineMatch[1]);
      if (Number.isFinite(sec) && sec > 0) {
        structuredRetryDelayMs = Math.round(sec * 1000);
      }
    }
  }

  const redacted = String(
    redactSensitiveMetadata(
      raw
        .replace(/AIza[0-9A-Za-z_-]{10,}/g, '[REDACTED_API_KEY]')
        .replace(/\s+/g, ' ')
        .slice(0, 160)
    )
  );

  return {
    combinedText: combined,
    structuredRetryDelayMs,
    sanitizedNote: redacted || 'provider_error',
  };
};

export const parseProviderRetryGuidanceMs = (
  retryAfterHeader: string | null | undefined,
  bodyText = '',
  nowMs: number = Date.now()
): ProviderRetryGuidance => {
  let headerDelayMs = 0;
  let hasValidHeader = false;

  if (typeof retryAfterHeader === 'string' && retryAfterHeader.trim().length > 0) {
    const trimmed = retryAfterHeader.trim();
    if (/^\d+(?:\.\d+)?$/.test(trimmed)) {
      const numericSec = Number(trimmed);
      if (Number.isFinite(numericSec) && numericSec >= 0 && numericSec <= 86_400) {
        headerDelayMs = Math.max(200, Math.round(numericSec * 1000));
        hasValidHeader = true;
      }
    } else {
      const parsedDateMs = Date.parse(trimmed);
      if (Number.isFinite(parsedDateMs) && parsedDateMs > nowMs) {
        headerDelayMs = Math.min(86_400_000, Math.max(200, parsedDateMs - nowMs));
        hasValidHeader = true;
      }
    }
  }

  const { structuredRetryDelayMs } = extractStructuredErrorTextAndDelay(bodyText);
  const bestDelayMs = Math.max(headerDelayMs, structuredRetryDelayMs);

  if (hasValidHeader || structuredRetryDelayMs > 0) {
    return {
      hasValidGuidance: true,
      retryDelayMs: Math.min(86_400_000, Math.max(200, bestDelayMs)),
    };
  }

  return { hasValidGuidance: false, retryDelayMs: 0 };
};

export const parseRetryAfterMs = (
  headerValue: string | null | undefined,
  capMs = MAX_IN_REQUEST_RETRY_WAIT_MS
): number => {
  const guidance = parseProviderRetryGuidanceMs(headerValue, '');
  if (!guidance.hasValidGuidance) return 0;
  return Math.min(guidance.retryDelayMs, capMs);
};

export const classifyGeminiHttpFailure = (status: number, bodyText: string): GeminiErrorCategory => {
  const { combinedText } = extractStructuredErrorTextAndDelay(bodyText);

  // Note: Google Gemini's generic 429 boilerplate always contains "please check your plan and billing details",
  // so we match explicit spend/billing-account exhaustion phrases rather than bare "billing details".
  const isSpendLimit =
    combinedText.includes('spend limit') ||
    combinedText.includes('spending limit') ||
    combinedText.includes('spend_limit') ||
    combinedText.includes('billing limit') ||
    combinedText.includes('billing account') ||
    combinedText.includes('billing quota') ||
    combinedText.includes('credit') ||
    combinedText.includes('budget') ||
    combinedText.includes('cost limit') ||
    combinedText.includes('monthly limit') ||
    combinedText.includes('account_balance');

  const isRpd =
    combinedText.includes('per day') ||
    combinedText.includes('per_day') ||
    combinedText.includes('perday') ||
    combinedText.includes('requests_per_day') ||
    combinedText.includes('requestsperday') ||
    /\brpd\b/.test(combinedText) ||
    combinedText.includes('daily') ||
    combinedText.includes('free_tier_requests') ||
    combinedText.includes('generate_content_free_tier_requests') ||
    combinedText.includes('limit: 0') ||
    combinedText.includes('day_limit');

  const isTpm =
    combinedText.includes('tokens per minute') ||
    combinedText.includes('tokens_per_minute') ||
    combinedText.includes('tokensperminute') ||
    /\btpm\b/.test(combinedText) ||
    combinedText.includes('token_count') ||
    combinedText.includes('input_token') ||
    combinedText.includes('token limit');

  const isRpm =
    combinedText.includes('requests per minute') ||
    combinedText.includes('requests_per_minute') ||
    combinedText.includes('requestsperminute') ||
    /\brpm\b/.test(combinedText) ||
    combinedText.includes('per minute') ||
    combinedText.includes('per_minute') ||
    combinedText.includes('rate limit exceeded') ||
    combinedText.includes('ratelimitexceeded') ||
    combinedText.includes('rate_limit_exceeded');

  if (status === 401 || status === 403) {
    if (isSpendLimit) return 'SPEND_LIMIT_EXHAUSTED';
    if (isRpd) return 'RPD_EXHAUSTED';
    return 'INVALID_API_KEY';
  }

  if (
    status === 400 &&
    (combinedText.includes('api_key_invalid') ||
      combinedText.includes('api key not valid') ||
      combinedText.includes('invalid api key'))
  ) {
    return 'INVALID_API_KEY';
  }

  if (
    status === 404 ||
    (status === 400 &&
      ((combinedText.includes('model') && combinedText.includes('not found')) ||
        combinedText.includes('not supported for this model') ||
        combinedText.includes('unsupported') ||
        combinedText.includes('invalid value at') ||
        combinedText.includes('thinking_level') ||
        combinedText.includes('thinkingconfig')))
  ) {
    return 'UNSUPPORTED_MODEL';
  }

  if (status === 429) {
    if (isRpd) return 'RPD_EXHAUSTED';
    if (isTpm) return 'RATE_LIMIT_TPM';
    if (isRpm) return 'RATE_LIMIT_RPM';
    if (isSpendLimit) return 'SPEND_LIMIT_EXHAUSTED';
    return 'UNKNOWN_RATE_LIMIT';
  }

  if (
    status === 502 ||
    status === 503 ||
    status === 504 ||
    status === 529 ||
    (status === 500 && (combinedText.includes('overloaded') || combinedText.includes('temporarily unavailable')))
  ) {
    return 'UPSTREAM_OVERLOADED';
  }

  return 'OTHER_ERROR';
};

const buildCircuitRedisKeyForCategory = (params: {
  credFp: string;
  quotaScopeId: string;
  modelSlug: string;
  opScope: GeminiOperationScope;
  category: GeminiErrorCategory;
}): string => {
  switch (params.category) {
    case 'INVALID_API_KEY':
      // Credential-specific authentication failure latch (scoped strictly to the offending API key)
      return `aegis:gemini:cb:cred:${params.credFp}:INVALID_API_KEY`;
    case 'SPEND_LIMIT_EXHAUSTED':
      // Google project / billing account spend limit (shared across all API keys in the project)
      return `aegis:gemini:cb:proj:${params.quotaScopeId}:global:SPEND_LIMIT_EXHAUSTED`;
    case 'RPD_EXHAUSTED':
      // Google project + model daily quota (shared across all API keys in the project)
      return `aegis:gemini:cb:proj:${params.quotaScopeId}:model:${params.modelSlug}:RPD_EXHAUSTED`;
    case 'UNKNOWN_RATE_LIMIT':
      return `aegis:gemini:cb:proj:${params.quotaScopeId}:model:${params.modelSlug}:UNKNOWN_RATE_LIMIT`;
    case 'RATE_LIMIT_RPM':
    case 'RATE_LIMIT_TPM':
      return `aegis:gemini:cb:proj:${params.quotaScopeId}:model:${params.modelSlug}:${params.opScope}:RATE_LIMIT`;
    case 'UPSTREAM_OVERLOADED':
    case 'TIMEOUT':
    default:
      return `aegis:gemini:cb:proj:${params.quotaScopeId}:model:${params.modelSlug}:TRANSIENT`;
  }
};

export const getScopedCircuitRedisKeysToInspect = (params: {
  credFp: string;
  quotaScopeId?: string;
  model: string;
  operationKind?: GeminiOperationKind;
}): string[] => {
  const modelSlug = normalizeModelSlug(params.model);
  const opScope = toOperationScope(params.operationKind);
  const quotaScopeId = params.quotaScopeId ?? getGeminiQuotaScopeId();
  return [
    `aegis:gemini:cb:cred:${params.credFp}:INVALID_API_KEY`,
    `aegis:gemini:cb:proj:${quotaScopeId}:global:SPEND_LIMIT_EXHAUSTED`,
    `aegis:gemini:cb:proj:${quotaScopeId}:model:${modelSlug}:RPD_EXHAUSTED`,
    `aegis:gemini:cb:proj:${quotaScopeId}:model:${modelSlug}:UNKNOWN_RATE_LIMIT`,
    `aegis:gemini:cb:proj:${quotaScopeId}:model:${modelSlug}:${opScope}:RATE_LIMIT`,
    `aegis:gemini:cb:proj:${quotaScopeId}:model:${modelSlug}:TRANSIENT`,
  ];
};

const isConstraintActive = (env: CircuitConstraintEnvelope, nowMs: number): boolean => {
  if (env.latched) return true;
  return typeof env.deadlineMs === 'number' && Number.isFinite(env.deadlineMs) && env.deadlineMs > nowMs;
};

/**
 * Selects the strongest active recovery constraint across multiple circuit envelopes.
 * Latched constraints (`INVALID_API_KEY`) always win first; otherwise the constraint
 * with the furthest `deadlineMs` wins (preventing short-lived circuits from shadowing long-lived ones).
 */
export const selectStrongestCircuitConstraint = (
  envelopes: readonly CircuitConstraintEnvelope[],
  nowMs: number = Date.now()
): CircuitConstraintEnvelope | null => {
  const active = envelopes.filter((e) => isConstraintActive(e, nowMs));
  if (active.length === 0) return null;

  return [...active].sort((a, b) => {
    if (a.latched !== b.latched) return a.latched ? -1 : 1;
    const deadlineA = a.deadlineMs ?? Number.MAX_SAFE_INTEGER;
    const deadlineB = b.deadlineMs ?? Number.MAX_SAFE_INTEGER;
    if (deadlineA !== deadlineB) return deadlineB - deadlineA;
    return (CATEGORY_SEVERITY_RANK[b.category] ?? 0) - (CATEGORY_SEVERITY_RANK[a.category] ?? 0);
  })[0]!;
};

const computeCategoryRecoveryPolicy = (params: {
  category: GeminiErrorCategory;
  retryGuidance: ProviderRetryGuidance;
  nowMs: number;
  spendLimitStrikeCount?: number;
  deterministicJitterMs?: number;
}): {
  opensImmediately: boolean;
  latched: boolean;
  deadlineMs: number | null;
  deadlineSource: CircuitDeadlineSource;
  redisTtlMs: number;
} => {
  const jitter =
    params.deterministicJitterMs !== undefined
      ? params.deterministicJitterMs
      : Math.floor(Math.random() * 1200);
  const guidedMs = params.retryGuidance.hasValidGuidance ? params.retryGuidance.retryDelayMs : 0;

  switch (params.category) {
    case 'INVALID_API_KEY':
      return {
        opensImmediately: true,
        latched: true,
        deadlineMs: null,
        deadlineSource: 'CREDENTIAL_LATCH',
        redisTtlMs: LATCHED_CREDENTIAL_REDIS_TTL_MS,
      };

    case 'RPD_EXHAUSTED': {
      const pacificResetMs = computeNextPacificMidnightResetMs(params.nowMs);
      const guidedDeadlineMs = params.nowMs + guidedMs;
      const useGuided = guidedDeadlineMs > pacificResetMs;
      const deadlineMs = Math.max(pacificResetMs, guidedDeadlineMs);
      return {
        opensImmediately: true,
        latched: false,
        deadlineMs,
        deadlineSource: useGuided ? 'PROVIDER_RETRY_AFTER' : 'PACIFIC_MIDNIGHT_CALCULATION',
        redisTtlMs: Math.max(1000, deadlineMs - params.nowMs),
      };
    }

    case 'SPEND_LIMIT_EXHAUSTED': {
      const configuredSpendWindow = Number(
        process.env.GEMINI_SPEND_LIMIT_COOLDOWN_MS ?? DEFAULT_SPEND_LIMIT_COOLDOWN_MS
      );
      const baseSpendMs =
        Number.isFinite(configuredSpendWindow) && configuredSpendWindow >= 60_000
          ? Math.round(configuredSpendWindow)
          : DEFAULT_SPEND_LIMIT_COOLDOWN_MS;
      const strikes = Math.max(1, params.spendLimitStrikeCount ?? 1);
      // Progressive exponential backoff on repeated spend-limit failures after cooldown expiry (1x -> 2x -> 4x, capped at 4h)
      const escalatedAppCooldownMs = Math.min(
        MAX_SPEND_LIMIT_COOLDOWN_MS,
        baseSpendMs * 2 ** Math.min(4, strikes - 1)
      );
      const useGuided = guidedMs > escalatedAppCooldownMs;
      const cooldownMs = Math.max(escalatedAppCooldownMs, guidedMs);
      return {
        opensImmediately: true,
        latched: false,
        deadlineMs: params.nowMs + cooldownMs,
        deadlineSource: useGuided ? 'PROVIDER_RETRY_AFTER' : 'APPLICATION_CONSERVATIVE_COOLDOWN',
        redisTtlMs: cooldownMs,
      };
    }

    case 'UNKNOWN_RATE_LIMIT': {
      const configuredUnknown = Number(
        process.env.GEMINI_UNKNOWN_429_COOLDOWN_MS ?? DEFAULT_UNKNOWN_429_COOLDOWN_MS
      );
      const baseUnknownMs =
        Number.isFinite(configuredUnknown) && configuredUnknown >= 10_000
          ? Math.round(configuredUnknown)
          : DEFAULT_UNKNOWN_429_COOLDOWN_MS;
      const useGuided = guidedMs > baseUnknownMs;
      const cooldownMs = Math.max(baseUnknownMs, guidedMs) + jitter;
      return {
        opensImmediately: true,
        latched: false,
        deadlineMs: params.nowMs + cooldownMs,
        deadlineSource: useGuided ? 'PROVIDER_RETRY_AFTER' : 'APPLICATION_CONSERVATIVE_COOLDOWN',
        redisTtlMs: cooldownMs,
      };
    }

    case 'RATE_LIMIT_RPM':
    case 'RATE_LIMIT_TPM': {
      const useGuided = guidedMs > DEFAULT_RPM_TPM_COOLDOWN_MS;
      const cooldownMs = Math.max(DEFAULT_RPM_TPM_COOLDOWN_MS, guidedMs) + jitter;
      return {
        opensImmediately: true,
        latched: false,
        deadlineMs: params.nowMs + cooldownMs,
        deadlineSource: useGuided ? 'PROVIDER_RETRY_AFTER' : 'APPLICATION_CONSERVATIVE_COOLDOWN',
        redisTtlMs: cooldownMs,
      };
    }

    case 'UPSTREAM_OVERLOADED':
    case 'TIMEOUT':
    default: {
      const useGuided = guidedMs > DEFAULT_TRANSIENT_OVERLOAD_COOLDOWN_MS;
      const cooldownMs = Math.max(DEFAULT_TRANSIENT_OVERLOAD_COOLDOWN_MS, guidedMs) + jitter;
      return {
        opensImmediately: guidedMs > MAX_IN_REQUEST_RETRY_WAIT_MS,
        latched: false,
        deadlineMs: params.nowMs + cooldownMs,
        deadlineSource: useGuided ? 'PROVIDER_RETRY_AFTER' : 'APPLICATION_CONSERVATIVE_COOLDOWN',
        redisTtlMs: cooldownMs,
      };
    }
  }
};

const sleepMs = (ms: number): Promise<void> =>
  new Promise((resolve) => {
    setTimeout(resolve, ms);
  });

const buildRequestHash = (
  quotaScopeId: string,
  credFp: string,
  model: string,
  parts: unknown[],
  jsonMode: boolean
): string => {
  return createHash('sha256')
    .update(quotaScopeId)
    .update(':')
    .update(credFp)
    .update(':')
    .update(model)
    .update(jsonMode ? ':json:' : ':text:')
    .update(JSON.stringify(parts))
    .digest('hex');
};

const parseCircuitEnvelopeJson = (raw: unknown): CircuitConstraintEnvelope | null => {
  if (typeof raw !== 'string' || !raw.trim()) return null;
  try {
    const parsed = JSON.parse(raw) as Partial<CircuitConstraintEnvelope>;
    if (
      parsed &&
      typeof parsed === 'object' &&
      typeof parsed.category === 'string' &&
      typeof parsed.credentialFingerprint === 'string'
    ) {
      return {
        category: parsed.category as GeminiErrorCategory,
        credentialFingerprint: parsed.credentialFingerprint,
        quotaScopeId:
          typeof parsed.quotaScopeId === 'string' && parsed.quotaScopeId.trim()
            ? parsed.quotaScopeId
            : 'proj_dev_default_unscoped',
        model: typeof parsed.model === 'string' ? parsed.model : DEFAULT_GEMINI_PRIMARY_MODEL,
        opScope:
          parsed.opScope === 'VISION_OCR' || parsed.opScope === 'TEXT' ? parsed.opScope : 'GLOBAL',
        openedAtMs: typeof parsed.openedAtMs === 'number' ? parsed.openedAtMs : 0,
        deadlineMs: typeof parsed.deadlineMs === 'number' ? parsed.deadlineMs : null,
        latched: Boolean(parsed.latched),
        deadlineSource:
          parsed.deadlineSource === 'PROVIDER_RETRY_AFTER' ||
          parsed.deadlineSource === 'PACIFIC_MIDNIGHT_CALCULATION' ||
          parsed.deadlineSource === 'CREDENTIAL_LATCH'
            ? parsed.deadlineSource
            : 'APPLICATION_CONSERVATIVE_COOLDOWN',
        strikeCount:
          typeof parsed.strikeCount === 'number' && parsed.strikeCount >= 1
            ? Math.round(parsed.strikeCount)
            : 1,
        sanitizedReason: typeof parsed.sanitizedReason === 'string' ? parsed.sanitizedReason : '',
        correlationId: typeof parsed.correlationId === 'string' ? parsed.correlationId : 'req-shared',
      };
    }
  } catch {
    // Ignore malformed payload
  }
  return null;
};

export class GeminiResilienceInstance {
  public readonly instanceId: string;
  private readonly localCircuits = new Map<string, CircuitConstraintEnvelope>();
  private readonly consecutiveFailuresByKey = new Map<string, number>();
  private readonly spendLimitStrikesByScope = new Map<string, number>();
  private readonly knownRedisKeysByCred = new Map<string, Set<string>>();
  private readonly knownRedisKeysByProjectScope = new Map<string, Set<string>>();
  private readonly inFlightDedupMap = new Map<string, Promise<GeminiRestExecutionResult>>();
  private activeCredentialFingerprint: string | null = null;
  private clockOffsetMs = 0;
  private lastObservedCategory: GeminiErrorCategory | null = null;
  private totalRequests = 0;
  private totalSuccesses = 0;
  private totalFallbacks = 0;
  private totalRetries = 0;
  private inFlightCount = 0;
  private inFlightVisionOcrCount = 0;

  constructor(instanceId = 'default-instance') {
    this.instanceId = instanceId;
  }

  public nowMs(): number {
    return Date.now() + this.clockOffsetMs;
  }

  public advanceClockForTest(elapsedMs: number): void {
    this.clockOffsetMs += elapsedMs;
  }

  public resetForTest(): void {
    this.localCircuits.clear();
    this.consecutiveFailuresByKey.clear();
    this.spendLimitStrikesByScope.clear();
    this.knownRedisKeysByCred.clear();
    this.knownRedisKeysByProjectScope.clear();
    this.inFlightDedupMap.clear();
    this.activeCredentialFingerprint = null;
    this.clockOffsetMs = 0;
    this.lastObservedCategory = null;
    this.totalRequests = 0;
    this.totalSuccesses = 0;
    this.totalFallbacks = 0;
    this.totalRetries = 0;
    this.inFlightCount = 0;
    this.inFlightVisionOcrCount = 0;
  }

  private trackRedisKey(credFp: string, quotaScopeId: string, redisKey: string): void {
    if (redisKey.includes(`:cred:${credFp}:`)) {
      let credSet = this.knownRedisKeysByCred.get(credFp);
      if (!credSet) {
        credSet = new Set<string>();
        this.knownRedisKeysByCred.set(credFp, credSet);
      }
      credSet.add(redisKey);
      return;
    }

    let projSet = this.knownRedisKeysByProjectScope.get(quotaScopeId);
    if (!projSet) {
      projSet = new Set<string>();
      this.knownRedisKeysByProjectScope.set(quotaScopeId, projSet);
    }
    projSet.add(redisKey);
  }

  /**
   * Reconciles credential fingerprint lifecycle on every operation:
   * When `GEMINI_API_KEY` rotates (`currentCredFp !== activeCredentialFingerprint`),
   * immediately purges ONLY the retired credential's `INVALID_API_KEY` circuit state from local RAM
   * and Redis while strictly preserving project-scoped (`proj_<24-hex>`) quota counters and
   * project-scoped circuits (`RPD_EXHAUSTED`, `SPEND_LIMIT_EXHAUSTED`, `RATE_LIMIT`, `TRANSIENT`).
   */
  private async reconcileCredentialLifecycle(currentCredFp: string): Promise<void> {
    if (this.activeCredentialFingerprint === currentCredFp) {
      return;
    }

    const retiredCredFp = this.activeCredentialFingerprint;
    this.activeCredentialFingerprint = currentCredFp;

    if (!retiredCredFp || retiredCredFp === 'cred_unconfigured') {
      return;
    }

    // 1. Purge ONLY retired credential-scoped state (`:cred:<retiredCredFp>:`) from local memory.
    // Project-scoped circuits (`:proj:<quotaScopeId>:`) MUST survive API key rotation within the same project!
    for (const k of Array.from(this.localCircuits.keys())) {
      if (k.includes(`:cred:${retiredCredFp}:`)) {
        this.localCircuits.delete(k);
      }
    }
    for (const k of Array.from(this.consecutiveFailuresByKey.keys())) {
      if (k.includes(`:cred:${retiredCredFp}:`)) {
        this.consecutiveFailuresByKey.delete(k);
      }
    }
    if (this.lastObservedCategory === 'INVALID_API_KEY') {
      this.lastObservedCategory = null;
    }

    // 2. Delete ONLY retired credential-scoped circuit keys in shared Redis
    const cfg = getUpstashConfig();
    if (!cfg) {
      this.knownRedisKeysByCred.delete(retiredCredFp);
      return;
    }

    const keysToDelete = new Set<string>([
      `aegis:gemini:cb:cred:${retiredCredFp}:INVALID_API_KEY`,
      ...(this.knownRedisKeysByCred.get(retiredCredFp) ?? []),
    ]);
    this.knownRedisKeysByCred.delete(retiredCredFp);

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 1500);
    try {
      await fetch(`${cfg.url}/multi-exec`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${cfg.token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(Array.from(keysToDelete).map((k) => ['DEL', k])),
        signal: controller.signal,
      });
    } catch {
      // Non-blocking cleanup; keys also carry bounded TTL in Redis.
    } finally {
      clearTimeout(timer);
    }
  }

  public getLocalActiveConstraint(params?: {
    model?: string;
    operationKind?: GeminiOperationKind;
    nowMs?: number;
  }): CircuitConstraintEnvelope | null {
    const now = params?.nowMs ?? this.nowMs();
    const credFp = getGeminiCredentialFingerprint();
    const quotaScopeId = getGeminiQuotaScopeId();
    const keysToInspect = params?.model
      ? getScopedCircuitRedisKeysToInspect({
          credFp,
          quotaScopeId,
          model: params.model,
          operationKind: params.operationKind,
        })
      : Array.from(this.localCircuits.keys()).filter(
          (k) => k.includes(`:cred:${credFp}:`) || k.includes(`:proj:${quotaScopeId}:`)
        );

    const candidates: CircuitConstraintEnvelope[] = [];
    for (const k of keysToInspect) {
      const env = this.localCircuits.get(k);
      if (env) {
        if (isConstraintActive(env, now)) {
          candidates.push(env);
        } else {
          this.localCircuits.delete(k);
        }
      }
    }
    return selectStrongestCircuitConstraint(candidates, now);
  }

  private mergeConstraintMonotonically(
    key: string,
    candidate: CircuitConstraintEnvelope,
    now: number
  ): CircuitConstraintEnvelope {
    this.trackRedisKey(candidate.credentialFingerprint, candidate.quotaScopeId, key);
    const existing = this.localCircuits.get(key);
    if (existing && isConstraintActive(existing, now)) {
      if (existing.latched) {
        return existing;
      }
      if (!candidate.latched && existing.deadlineMs !== null && candidate.deadlineMs !== null) {
        if (existing.deadlineMs >= candidate.deadlineMs) {
          return {
            ...existing,
            strikeCount: Math.max(existing.strikeCount, candidate.strikeCount),
          };
        }
      }
    }
    this.localCircuits.set(key, candidate);
    return candidate;
  }

  private async persistCircuitConstraintToRedis(
    redisKey: string,
    envelope: CircuitConstraintEnvelope,
    redisTtlMs: number,
    now: number
  ): Promise<CircuitConstraintEnvelope> {
    const cfg = getUpstashConfig();
    if (!cfg) return envelope;

    const safeTtlMs = Math.max(1000, Math.round(redisTtlMs));
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 1800);
    try {
      const res = await fetch(`${cfg.url}/multi-exec`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${cfg.token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify([
          [
            'EVAL',
            ATOMIC_MONOTONIC_CIRCUIT_SET_LUA,
            1,
            redisKey,
            JSON.stringify(envelope),
            String(envelope.deadlineMs ?? -1),
            envelope.latched ? '1' : '0',
            String(safeTtlMs),
            String(now),
          ],
        ]),
        signal: controller.signal,
      });

      if (res.ok) {
        const data = (await res.json()) as UpstashCommandEntry[];
        const evalResult = Array.isArray(data) ? data[0]?.result : null;
        if (Array.isArray(evalResult) && typeof evalResult[1] === 'string') {
          const authoritative = parseCircuitEnvelopeJson(evalResult[1]);
          if (authoritative) {
            return this.mergeConstraintMonotonically(redisKey, authoritative, now);
          }
        }
      }
    } catch {
      // Best-effort distributed broadcast; local circuit state is already updated.
    } finally {
      clearTimeout(timer);
    }
    return envelope;
  }

  /**
   * Single-Step Atomic Distributed Circuit Check & Weighted Sliding-Window Quota Reservation via Redis Lua `EVAL`.
   * - Inspects the credential-specific `INVALID_API_KEY` key (`cred_<24-hex>`) AND all 5 project-scoped
   *   circuit keys (`proj_<24-hex>`), then checks and increments project-scoped RPM & OCR RPM counters atomically.
   * - Eliminates the Phase-1-to-Phase-2 check-to-increment race window inside Redis.
   * - Rejected requests (open circuit or exceeded RPM/OCR quota) never increment Redis counters.
   * - Fails closed when `AEGIS_REQUIRE_DISTRIBUTED_RATE_LIMIT=true` (or `AEGIS_PRODUCTION_STRICT_READINESS=true`)
   *   and Redis errors or times out.
   */
  private async reserveDistributedCircuitAndSlidingQuotaAtomically(params: {
    credFp: string;
    quotaScopeId: string;
    model: string;
    operationKind: GeminiOperationKind;
    now: number;
  }): Promise<{
    allowed: boolean;
    reason?: GeminiErrorCategory;
    sharedCircuitOpen?: boolean;
    failClosedRedisError?: boolean;
    activeEnvelope?: CircuitConstraintEnvelope;
  }> {
    const cfg = getUpstashConfig();
    const requireStrictRedis =
      process.env.AEGIS_REQUIRE_DISTRIBUTED_RATE_LIMIT === 'true' ||
      process.env.AEGIS_PRODUCTION_STRICT_READINESS === 'true';

    if (!cfg) {
      if (requireStrictRedis) {
        return {
          allowed: false,
          reason: 'UNKNOWN_RATE_LIMIT',
          failClosedRedisError: true,
        };
      }
      return { allowed: true };
    }

    const circuitKeys = getScopedCircuitRedisKeysToInspect({
      credFp: params.credFp,
      quotaScopeId: params.quotaScopeId,
      model: params.model,
      operationKind: params.operationKind,
    });
    for (const ck of circuitKeys) {
      this.trackRedisKey(params.credFp, params.quotaScopeId, ck);
    }

    const globalRpmMax = Math.max(1, Number(process.env.GEMINI_GLOBAL_RPM_LIMIT ?? 30));
    const globalOcrRpmMax = Math.max(1, Number(process.env.GEMINI_GLOBAL_OCR_RPM_LIMIT ?? 12));
    const currBucket = Math.floor(params.now / 60_000);
    const prevBucket = currBucket - 1;
    const elapsedRatio = (params.now % 60_000) / 60_000;
    const oneMinusElapsedRatioMillis = Math.max(0, Math.min(1000, Math.round((1 - elapsedRatio) * 1000)));

    // Project-scoped quota counters: shared across all API keys belonging to the same Google project
    const currRpmKey = `aegis:gemini:quota:${params.quotaScopeId}:rpm:${currBucket}`;
    const prevRpmKey = `aegis:gemini:quota:${params.quotaScopeId}:rpm:${prevBucket}`;
    const currOcrKey = `aegis:gemini:quota:${params.quotaScopeId}:ocr:rpm:${currBucket}`;
    const prevOcrKey = `aegis:gemini:quota:${params.quotaScopeId}:ocr:rpm:${prevBucket}`;

    const allKeys = [...circuitKeys, currRpmKey, prevRpmKey, currOcrKey, prevOcrKey];
    const argv = [
      String(params.now),
      String(globalRpmMax),
      String(globalOcrRpmMax),
      params.operationKind === 'VISION_OCR' ? '1' : '0',
      String(SLIDING_WINDOW_BUCKET_TTL_MS),
      String(oneMinusElapsedRatioMillis),
    ];

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 1800);
    try {
      const res = await fetch(`${cfg.url}/multi-exec`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${cfg.token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify([
          ['EVAL', ATOMIC_CIRCUIT_GATE_AND_QUOTA_RESERVE_LUA, allKeys.length, ...allKeys, ...argv],
        ]),
        signal: controller.signal,
      });

      if (!res.ok) {
        return requireStrictRedis
          ? { allowed: false, reason: 'UNKNOWN_RATE_LIMIT', failClosedRedisError: true }
          : { allowed: true };
      }

      const data = (await res.json()) as unknown;
      if (!Array.isArray(data) || data.length < 1) {
        return requireStrictRedis
          ? { allowed: false, reason: 'UNKNOWN_RATE_LIMIT', failClosedRedisError: true }
          : { allowed: true };
      }

      const entry = data[0] as UpstashCommandEntry | undefined;
      if (!entry || typeof entry.error === 'string' || !Array.isArray(entry.result)) {
        return requireStrictRedis
          ? { allowed: false, reason: 'UNKNOWN_RATE_LIMIT', failClosedRedisError: true }
          : { allowed: true };
      }

      const tuple = entry.result as unknown[];
      const verdict = String(tuple[0] ?? '');

      if (verdict === 'CIRCUIT_OPEN') {
        const parsedEnvelopes: CircuitConstraintEnvelope[] = [];
        for (let i = 0; i < circuitKeys.length; i += 1) {
          const rawEnv = tuple[i + 1];
          const env = parseCircuitEnvelopeJson(rawEnv);
          if (env && isConstraintActive(env, params.now)) {
            this.mergeConstraintMonotonically(circuitKeys[i]!, env, params.now);
            if (env.category === 'SPEND_LIMIT_EXHAUSTED') {
              const prevStrikes = this.spendLimitStrikesByScope.get(params.quotaScopeId) ?? 0;
              this.spendLimitStrikesByScope.set(
                params.quotaScopeId,
                Math.max(prevStrikes, env.strikeCount)
              );
            }
            parsedEnvelopes.push(env);
          }
        }
        const strongest = selectStrongestCircuitConstraint(parsedEnvelopes, params.now);
        if (strongest) {
          this.lastObservedCategory = strongest.category;
          return {
            allowed: false,
            reason: strongest.category,
            sharedCircuitOpen: true,
            activeEnvelope: strongest,
          };
        }
        return {
          allowed: false,
          reason: 'UNKNOWN_RATE_LIMIT',
          sharedCircuitOpen: true,
        };
      }

      if (verdict === 'QUOTA_RPM_EXCEEDED' || verdict === 'QUOTA_OCR_EXCEEDED') {
        return {
          allowed: false,
          reason: 'RATE_LIMIT_RPM',
        };
      }

      if (verdict === 'ALLOWED') {
        const committedRpm = Number(tuple[1]);
        if (!Number.isInteger(committedRpm) || committedRpm < 1) {
          return requireStrictRedis
            ? { allowed: false, reason: 'UNKNOWN_RATE_LIMIT', failClosedRedisError: true }
            : { allowed: true };
        }
        return { allowed: true };
      }

      return requireStrictRedis
        ? { allowed: false, reason: 'UNKNOWN_RATE_LIMIT', failClosedRedisError: true }
        : { allowed: true };
    } catch {
      if (requireStrictRedis) {
        return { allowed: false, reason: 'UNKNOWN_RATE_LIMIT', failClosedRedisError: true };
      }
      return { allowed: true };
    } finally {
      clearTimeout(timer);
    }
  }

  private async recordFailure(params: {
    category: GeminiErrorCategory;
    credFp: string;
    quotaScopeId: string;
    model: string;
    operationKind: GeminiOperationKind;
    retryGuidance: ProviderRetryGuidance;
    sanitizedNote: string;
    correlationId: string;
  }): Promise<CircuitConstraintEnvelope | null> {
    this.totalFallbacks += 1;
    this.lastObservedCategory = params.category;

    const now = this.nowMs();
    const modelSlug = normalizeModelSlug(params.model);
    const opScope = toOperationScope(params.operationKind);
    const redisKey = buildCircuitRedisKeyForCategory({
      credFp: params.credFp,
      quotaScopeId: params.quotaScopeId,
      modelSlug,
      opScope,
      category: params.category,
    });

    let spendStrikeCount = 1;
    if (params.category === 'SPEND_LIMIT_EXHAUSTED') {
      spendStrikeCount = (this.spendLimitStrikesByScope.get(params.quotaScopeId) ?? 0) + 1;
      this.spendLimitStrikesByScope.set(params.quotaScopeId, spendStrikeCount);
    }

    const policy = computeCategoryRecoveryPolicy({
      category: params.category,
      retryGuidance: params.retryGuidance,
      nowMs: now,
      spendLimitStrikeCount: spendStrikeCount,
    });

    const failureCount = (this.consecutiveFailuresByKey.get(redisKey) ?? 0) + 1;
    this.consecutiveFailuresByKey.set(redisKey, failureCount);

    const shouldOpen = policy.opensImmediately || failureCount >= FAILURE_THRESHOLD_TO_OPEN;
    if (!shouldOpen) {
      return null;
    }

    const envelope: CircuitConstraintEnvelope = {
      category: params.category,
      credentialFingerprint: params.credFp,
      quotaScopeId: params.quotaScopeId,
      model: modelSlug,
      opScope:
        params.category === 'INVALID_API_KEY' || params.category === 'SPEND_LIMIT_EXHAUSTED'
          ? 'GLOBAL'
          : opScope,
      openedAtMs: now,
      deadlineMs: policy.deadlineMs,
      latched: policy.latched,
      deadlineSource: policy.deadlineSource,
      strikeCount: spendStrikeCount,
      sanitizedReason: params.sanitizedNote,
      correlationId: params.correlationId,
    };

    const localEffective = this.mergeConstraintMonotonically(redisKey, envelope, now);
    const authoritative = await this.persistCircuitConstraintToRedis(
      redisKey,
      localEffective,
      policy.redisTtlMs,
      now
    );

    logStructuredEvent({
      level: params.category === 'INVALID_API_KEY' || params.category === 'RPD_EXHAUSTED' ? 'ERROR' : 'WARN',
      requestId: params.correlationId,
      route: 'gemini-resilience',
      action: 'GEMINI_CIRCUIT_OPENED',
      status: authoritative.latched ? 'LATCHED' : 'OPEN',
      errorCode: authoritative.category,
      metadata: {
        instanceId: this.instanceId,
        model: modelSlug,
        opScope: authoritative.opScope,
        credentialFingerprint: params.credFp,
        quotaScopeId: params.quotaScopeId,
        deadlineSource: authoritative.deadlineSource,
        spendLimitStrikeCount:
          authoritative.category === 'SPEND_LIMIT_EXHAUSTED' ? authoritative.strikeCount : undefined,
        recoveryDeadlineIso: authoritative.deadlineMs
          ? new Date(authoritative.deadlineMs).toISOString()
          : 'LATCHED_UNTIL_CREDENTIAL_CHANGE_OR_ADMIN_RESET',
        sanitizedProviderNote: authoritative.sanitizedReason,
      },
    });

    return authoritative;
  }

  private recordSuccess(
    credFp: string,
    quotaScopeId: string,
    model: string,
    operationKind: GeminiOperationKind
  ): void {
    const modelSlug = normalizeModelSlug(model);
    const opScope = toOperationScope(operationKind);
    const transientKey = `aegis:gemini:cb:proj:${quotaScopeId}:model:${modelSlug}:TRANSIENT`;
    const rateKey = `aegis:gemini:cb:proj:${quotaScopeId}:model:${modelSlug}:${opScope}:RATE_LIMIT`;
    const credKey = `aegis:gemini:cb:cred:${credFp}:INVALID_API_KEY`;
    this.consecutiveFailuresByKey.delete(transientKey);
    this.consecutiveFailuresByKey.delete(rateKey);
    this.consecutiveFailuresByKey.delete(credKey);
    this.spendLimitStrikesByScope.delete(quotaScopeId);
    this.totalSuccesses += 1;
  }

  public async authorizeAdminCircuitReset(params: {
    adminToken: string;
    credentialFingerprint?: string;
    quotaScopeId?: string;
  }): Promise<{ ok: boolean; clearedCount: number; errorCode?: string }> {
    const validation = validateAdminResetSecretConfiguration();
    if (!validation.valid || !params.adminToken) {
      return { ok: false, clearedCount: 0, errorCode: 'UNAUTHORIZED_ADMIN_RESET' };
    }

    const aBuf = Buffer.from(params.adminToken.trim(), 'utf8');
    const bBuf = Buffer.from(validation.secret!, 'utf8');
    if (aBuf.length !== bBuf.length || !timingSafeEqual(aBuf, bBuf)) {
      return { ok: false, clearedCount: 0, errorCode: 'UNAUTHORIZED_ADMIN_RESET' };
    }

    const targetCredFp = params.credentialFingerprint ?? getGeminiCredentialFingerprint();
    const targetQuotaScopeId = params.quotaScopeId ?? getGeminiQuotaScopeId();
    let clearedCount = 0;

    for (const k of Array.from(this.localCircuits.keys())) {
      if (k.includes(`:cred:${targetCredFp}:`) || k.includes(`:proj:${targetQuotaScopeId}:`)) {
        this.localCircuits.delete(k);
        clearedCount += 1;
      }
    }
    this.consecutiveFailuresByKey.clear();
    this.spendLimitStrikesByScope.delete(targetQuotaScopeId);

    const cfg = getUpstashConfig();
    if (cfg) {
      const keysToDelete = new Set<string>([
        `aegis:gemini:cb:cred:${targetCredFp}:INVALID_API_KEY`,
        `aegis:gemini:cb:proj:${targetQuotaScopeId}:global:SPEND_LIMIT_EXHAUSTED`,
        ...(this.knownRedisKeysByCred.get(targetCredFp) ?? []),
        ...(this.knownRedisKeysByProjectScope.get(targetQuotaScopeId) ?? []),
      ]);
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 1800);
      try {
        await fetch(`${cfg.url}/multi-exec`, {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${cfg.token}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(Array.from(keysToDelete).map((k) => ['DEL', k])),
          signal: controller.signal,
        });
      } catch {
        // Ignore Redis clear failure during local reset
      } finally {
        clearTimeout(timer);
      }
    }

    logStructuredEvent({
      level: 'INFO',
      route: 'gemini-resilience',
      action: 'ADMIN_GEMINI_CIRCUIT_RESET',
      status: 'CLEARED',
      metadata: {
        instanceId: this.instanceId,
        credentialFingerprint: targetCredFp,
        quotaScopeId: targetQuotaScopeId,
        clearedCount,
      },
    });

    return { ok: true, clearedCount };
  }

  public async executeGenerateContent(params: {
    model: string;
    parts: unknown[];
    jsonMode: boolean;
    timeoutMs?: number;
    maxTransientRetries?: number;
    operationKind?: GeminiOperationKind;
  }): Promise<GeminiRestExecutionResult> {
    if (isE2eExternalAiDisabled()) {
      this.totalFallbacks += 1;
      logStructuredEvent({
        level: 'INFO',
        route: 'gemini-resilience',
        action: 'GEMINI_E2E_ISOLATION_BLOCKED',
        status: 'BLOCKED_LOCAL_E2E',
        metadata: {
          instanceId: this.instanceId,
          model: params.model,
          operationKind: params.operationKind ?? 'INVESTIGATION',
        },
      });
      return {
        text: null,
        ok: false,
        category: 'E2E_ISOLATED_LOCAL_ONLY',
        e2eIsolated: true,
        attempts: 0,
      };
    }

    const apiKey = process.env.GEMINI_API_KEY?.trim();
    if (!apiKey || apiKey === 'your_gemini_api_key_here') {
      return {
        text: null,
        ok: false,
        category: 'INVALID_API_KEY',
        attempts: 0,
      };
    }

    const credFp = getGeminiCredentialFingerprint(apiKey);
    await this.reconcileCredentialLifecycle(credFp);

    const quotaScopeStatus = getGeminiQuotaScopeStatus();
    if (quotaScopeStatus.mode === 'MISCONFIGURED_FAIL_CLOSED' || !quotaScopeStatus.scopeId) {
      this.totalFallbacks += 1;
      return {
        text: null,
        ok: false,
        category: 'UNKNOWN_RATE_LIMIT',
        circuitTripped: true,
        failClosedQuotaScopeError: true,
        attempts: 0,
      };
    }
    const quotaScopeId = quotaScopeStatus.scopeId;

    const now = this.nowMs();
    const operationKind: GeminiOperationKind = params.operationKind ?? 'INVESTIGATION';

    const localConstraint = this.getLocalActiveConstraint({
      model: params.model,
      operationKind,
      nowMs: now,
    });
    if (localConstraint) {
      this.totalFallbacks += 1;
      return {
        text: null,
        ok: false,
        category: localConstraint.category,
        circuitTripped: true,
        recoveryDeadlineMs: localConstraint.deadlineMs,
        deadlineSource: localConstraint.deadlineSource,
        latched: localConstraint.latched,
        attempts: 0,
      };
    }

    const dedupKey = buildRequestHash(
      quotaScopeId,
      credFp,
      params.model,
      params.parts,
      params.jsonMode
    );
    const existingFlight = this.inFlightDedupMap.get(dedupKey);
    if (existingFlight) {
      const shared = await existingFlight;
      return { ...shared, deduplicated: true };
    }

    if (
      this.inFlightCount >= PER_INSTANCE_MAX_CONCURRENT_GEMINI ||
      (operationKind === 'VISION_OCR' &&
        this.inFlightVisionOcrCount >= PER_INSTANCE_MAX_CONCURRENT_VISION_OCR)
    ) {
      this.totalFallbacks += 1;
      return {
        text: null,
        ok: false,
        category: 'RATE_LIMIT_RPM',
        circuitTripped: true,
        attempts: 0,
      };
    }

    const timeoutMs = params.timeoutMs ?? 7500;
    const maxRetries = Math.min(Math.max(params.maxTransientRetries ?? 1, 0), 2);
    const correlationId = generateRequestTraceId();

    const runPromise = (async (): Promise<GeminiRestExecutionResult> => {
      this.inFlightCount += 1;
      if (operationKind === 'VISION_OCR') {
        this.inFlightVisionOcrCount += 1;
      }
      this.totalRequests += 1;
      let attempts = 0;

      try {
        const distCheck = await this.reserveDistributedCircuitAndSlidingQuotaAtomically({
          credFp,
          quotaScopeId,
          model: params.model,
          operationKind,
          now: this.nowMs(),
        });
        if (!distCheck.allowed) {
          this.totalFallbacks += 1;
          return {
            text: null,
            ok: false,
            category: distCheck.reason ?? 'RATE_LIMIT_RPM',
            circuitTripped: true,
            distributedQuotaTripped: true,
            failClosedRedisError: distCheck.failClosedRedisError,
            recoveryDeadlineMs: distCheck.activeEnvelope?.deadlineMs ?? null,
            deadlineSource: distCheck.activeEnvelope?.deadlineSource ?? null,
            latched: distCheck.activeEnvelope?.latched ?? false,
            attempts: 0,
          };
        }

        for (let attempt = 0; attempt <= maxRetries; attempt += 1) {
          // Pre-attempt local circuit re-check (aborts in-request retry if circuit opened during backoff)
          const preAttemptConstraint = this.getLocalActiveConstraint({
            model: params.model,
            operationKind,
            nowMs: this.nowMs(),
          });
          if (preAttemptConstraint) {
            return {
              text: null,
              ok: false,
              category: preAttemptConstraint.category,
              circuitTripped: true,
              recoveryDeadlineMs: preAttemptConstraint.deadlineMs,
              deadlineSource: preAttemptConstraint.deadlineSource,
              latched: preAttemptConstraint.latched,
              attempts,
            };
          }

          attempts += 1;
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), timeoutMs);

          try {
            const response = await fetch(`${GEMINI_BASE_URL}/${params.model}:generateContent`, {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                'x-goog-api-key': apiKey,
              },
              body: JSON.stringify({
                contents: [{ role: 'user', parts: params.parts }],
                generationConfig: buildGeminiGenerationConfig({
                  model: params.model,
                  jsonMode: params.jsonMode,
                  operationKind,
                }),
              }),
              signal: controller.signal,
            });

            if (!response.ok) {
              const errBody = await response.text().catch(() => '');
              const category = classifyGeminiHttpFailure(response.status, errBody);
              const retryGuidance = parseProviderRetryGuidanceMs(
                response.headers.get('retry-after'),
                errBody,
                this.nowMs()
              );
              const { sanitizedNote } = extractStructuredErrorTextAndDelay(errBody);

              const isTransientRetryableCategory =
                category === 'RATE_LIMIT_RPM' ||
                category === 'RATE_LIMIT_TPM' ||
                category === 'UPSTREAM_OVERLOADED';

              // Never shorten a provider-required wait > 4000ms down to 4000ms to retry inside the same request!
              const exceedsInRequestRetryBudget =
                retryGuidance.hasValidGuidance &&
                retryGuidance.retryDelayMs > MAX_IN_REQUEST_RETRY_WAIT_MS;

              const canRetryInRequest =
                attempt < maxRetries &&
                isTransientRetryableCategory &&
                !exceedsInRequestRetryBudget;

              if (canRetryInRequest) {
                const jitterBackoff = Math.min(
                  2500,
                  400 * 2 ** attempt + Math.floor(Math.random() * 250)
                );
                const waitMs = retryGuidance.hasValidGuidance
                  ? retryGuidance.retryDelayMs
                  : jitterBackoff;
                this.totalRetries += 1;
                await sleepMs(waitMs);
                continue;
              }

              const openedEnv = await this.recordFailure({
                category,
                credFp,
                quotaScopeId,
                model: params.model,
                operationKind,
                retryGuidance,
                sanitizedNote,
                correlationId,
              });

              return {
                text: null,
                ok: false,
                category,
                httpStatus: response.status,
                circuitTripped: Boolean(openedEnv),
                recoveryDeadlineMs: openedEnv?.deadlineMs ?? null,
                deadlineSource: openedEnv?.deadlineSource ?? null,
                latched: openedEnv?.latched ?? false,
                attempts,
              };
            }

            const data = (await response.json()) as {
              candidates?: Array<{ content?: { parts?: GeminiCandidatePart[] } }>;
            };
            const text = extractPrimaryCandidateText(data);
            if (typeof text === 'string' && text.trim()) {
              this.recordSuccess(credFp, quotaScopeId, params.model, operationKind);
              return { text: text.trim(), ok: true, httpStatus: response.status, attempts };
            }

            const openedEnv = await this.recordFailure({
              category: 'OTHER_ERROR',
              credFp,
              quotaScopeId,
              model: params.model,
              operationKind,
              retryGuidance: { hasValidGuidance: false, retryDelayMs: 0 },
              sanitizedNote: 'empty_candidate_text',
              correlationId,
            });
            return {
              text: null,
              ok: false,
              category: 'OTHER_ERROR',
              httpStatus: response.status,
              circuitTripped: Boolean(openedEnv),
              attempts,
            };
          } catch (err) {
            const isAbort = err instanceof Error && err.name === 'AbortError';
            const category: GeminiErrorCategory = isAbort ? 'TIMEOUT' : 'OTHER_ERROR';
            const openedEnv = await this.recordFailure({
              category,
              credFp,
              quotaScopeId,
              model: params.model,
              operationKind,
              retryGuidance: { hasValidGuidance: false, retryDelayMs: 0 },
              sanitizedNote: isAbort ? 'request_timeout' : 'network_exception',
              correlationId,
            });
            return {
              text: null,
              ok: false,
              category,
              circuitTripped: Boolean(openedEnv),
              recoveryDeadlineMs: openedEnv?.deadlineMs ?? null,
              deadlineSource: openedEnv?.deadlineSource ?? null,
              attempts,
            };
          } finally {
            clearTimeout(timer);
          }
        }

        return { text: null, ok: false, category: 'OTHER_ERROR', attempts };
      } finally {
        this.inFlightCount = Math.max(0, this.inFlightCount - 1);
        if (operationKind === 'VISION_OCR') {
          this.inFlightVisionOcrCount = Math.max(0, this.inFlightVisionOcrCount - 1);
        }
        this.inFlightDedupMap.delete(dedupKey);
      }
    })();

    this.inFlightDedupMap.set(dedupKey, runPromise);
    return runPromise;
  }

  public getOperationalMetrics(model?: string): {
    mode: GeminiOperationalMode;
    aiEngineReady: boolean;
    circuitState: 'CLOSED' | 'OPEN';
    latched: boolean;
    cooldownRemainingMs: number;
    recoveryDeadlineMs: number | null;
    deadlineSource: CircuitDeadlineSource | null;
    spendLimitStrikeCount: number;
    consecutiveFailures: number;
    lastErrorCategory: GeminiErrorCategory | null;
    credentialFingerprint: string;
    quotaScopeId: string;
    quotaScopeMode: GeminiQuotaScopeMode;
    concurrencyScope: GeminiConcurrencyScope;
    perInstanceMaxConcurrentGemini: number;
    perInstanceMaxConcurrentVisionOcr: number;
    totalRequests: number;
    totalSuccesses: number;
    totalFallbacks: number;
    totalRetries: number;
    inFlightCount: number;
    inFlightVisionOcrCount: number;
    activeDedupKeysCount: number;
  } {
    const now = this.nowMs();
    const configured = hasConfiguredGeminiKey();
    const credFp = getGeminiCredentialFingerprint();
    const quotaScopeStatus = getGeminiQuotaScopeStatus();
    const quotaScopeId = quotaScopeStatus.scopeId ?? 'proj_misconfigured_fail_closed';

    if (this.activeCredentialFingerprint && this.activeCredentialFingerprint !== credFp) {
      void this.reconcileCredentialLifecycle(credFp);
    } else if (!this.activeCredentialFingerprint) {
      this.activeCredentialFingerprint = credFp;
    }

    const strongest = this.getLocalActiveConstraint({ model, nowMs: now });
    const openNow =
      Boolean(strongest) || quotaScopeStatus.mode === 'MISCONFIGURED_FAIL_CLOSED';
    const cooldownRemainingMs = openNow
      ? strongest?.latched
        ? Number.MAX_SAFE_INTEGER
        : Math.max(0, (strongest?.deadlineMs ?? now) - now)
      : 0;

    let mode: GeminiOperationalMode = 'AI_LIVE';
    if (!configured) {
      mode = 'AI_UNCONFIGURED';
    } else if (openNow) {
      mode = 'AI_COOLDOWN_DEGRADED';
    }

    let maxConsecutive = 0;
    for (const [k, c] of this.consecutiveFailuresByKey.entries()) {
      if ((k.includes(`:cred:${credFp}:`) || k.includes(`:proj:${quotaScopeId}:`)) && c > maxConsecutive) {
        maxConsecutive = c;
      }
    }

    return {
      mode,
      aiEngineReady: configured && !openNow,
      circuitState: openNow ? 'OPEN' : 'CLOSED',
      latched: Boolean(strongest?.latched),
      cooldownRemainingMs,
      recoveryDeadlineMs: strongest?.deadlineMs ?? null,
      deadlineSource: strongest?.deadlineSource ?? null,
      spendLimitStrikeCount: this.spendLimitStrikesByScope.get(quotaScopeId) ?? 0,
      consecutiveFailures: maxConsecutive,
      lastErrorCategory: strongest?.category ?? this.lastObservedCategory,
      credentialFingerprint: credFp,
      quotaScopeId,
      quotaScopeMode: quotaScopeStatus.mode,
      concurrencyScope: 'PER_INSTANCE_PROCESS_LOCAL',
      perInstanceMaxConcurrentGemini: PER_INSTANCE_MAX_CONCURRENT_GEMINI,
      perInstanceMaxConcurrentVisionOcr: PER_INSTANCE_MAX_CONCURRENT_VISION_OCR,
      totalRequests: this.totalRequests,
      totalSuccesses: this.totalSuccesses,
      totalFallbacks: this.totalFallbacks,
      totalRetries: this.totalRetries,
      inFlightCount: this.inFlightCount,
      inFlightVisionOcrCount: this.inFlightVisionOcrCount,
      activeDedupKeysCount: this.inFlightDedupMap.size,
    };
  }
}

const defaultInstance = new GeminiResilienceInstance('primary-instance');

export const createGeminiResilienceInstance = (instanceId: string): GeminiResilienceInstance => {
  return new GeminiResilienceInstance(instanceId);
};

export const executeResilientGeminiGenerateContent = async (params: {
  model: string;
  parts: unknown[];
  jsonMode: boolean;
  timeoutMs?: number;
  maxTransientRetries?: number;
  operationKind?: GeminiOperationKind;
}): Promise<GeminiRestExecutionResult> => {
  return defaultInstance.executeGenerateContent(params);
};

export const getGeminiOperationalMetrics = (model?: string) => {
  return defaultInstance.getOperationalMetrics(model);
};

export const MIN_ADMIN_RESET_SECRET_LENGTH = 32;

export interface AdminResetSecretValidationResult {
  valid: boolean;
  reason?: 'MISSING_ADMIN_RESET_SECRET' | 'WEAK_ADMIN_RESET_SECRET' | 'SECRET_DOMAIN_COLLISION';
  secret?: string;
}

/**
 * Validates dedicated `AEGIS_ADMIN_RESET_SECRET` domain separation (Wave 4.2.1B REDIS-02):
 * - Never falls back to `AEGIS_SESSION_SECRET` or any other secret.
 * - Requires >= 32 characters (aligned with strict secret policy across health/session/PII modules).
 * - Rejects reuse of `AEGIS_SESSION_SECRET`, `AEGIS_SESSION_SECRET_PREVIOUS`,
 *   `AEGIS_DIAGNOSTICS_SECRET`, `AEGIS_PII_HMAC_KEY`, or `AEGIS_PII_HMAC_KEY_PREVIOUS`.
 * - Never includes any secret value in error reasons or logs.
 */
export const validateAdminResetSecretConfiguration = (
  env: NodeJS.ProcessEnv = process.env
): AdminResetSecretValidationResult => {
  const configured = (env.AEGIS_ADMIN_RESET_SECRET ?? '').trim();
  if (!configured) {
    return { valid: false, reason: 'MISSING_ADMIN_RESET_SECRET' };
  }
  if (configured.length < MIN_ADMIN_RESET_SECRET_LENGTH) {
    return { valid: false, reason: 'WEAK_ADMIN_RESET_SECRET' };
  }

  const forbiddenReuseValues = [
    env.AEGIS_SESSION_SECRET?.trim(),
    env.AEGIS_SESSION_SECRET_PREVIOUS?.trim(),
    env.AEGIS_DIAGNOSTICS_SECRET?.trim(),
    env.AEGIS_PII_HMAC_KEY?.trim(),
    env.AEGIS_PII_HMAC_KEY_PREVIOUS?.trim(),
  ].filter((v): v is string => Boolean(v && v.length > 0));

  const configuredBuf = Buffer.from(configured, 'utf8');
  for (const other of forbiddenReuseValues) {
    const otherBuf = Buffer.from(other, 'utf8');
    if (configuredBuf.length === otherBuf.length && timingSafeEqual(configuredBuf, otherBuf)) {
      return { valid: false, reason: 'SECRET_DOMAIN_COLLISION' };
    }
  }

  return { valid: true, secret: configured };
};

export const authorizeAdminGeminiCircuitReset = async (params: {
  adminToken: string;
  credentialFingerprint?: string;
  quotaScopeId?: string;
}) => {
  return defaultInstance.authorizeAdminCircuitReset(params);
};

export const advanceGeminiCircuitCooldownForTest = (elapsedMs: number): void => {
  defaultInstance.advanceClockForTest(elapsedMs);
};

export const resetGeminiResilienceForTest = (): void => {
  defaultInstance.resetForTest();
};
