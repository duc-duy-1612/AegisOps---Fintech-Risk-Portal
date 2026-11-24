/**
 * Wave 4.1.1 Distributed Rate Limiter (Upstash Redis REST `/multi-exec` Atomic Transactions + Fail-Closed).
 *
 * - Uses Upstash Redis REST `/multi-exec` (`MULTI`/`EXEC` transaction), NOT `/pipeline`, because
 *   Upstash `/pipeline` only batches HTTP round-trips without transactional atomicity.
 * - Atomically executes `INCR <key>` + `PEXPIRE <key> <windowMs> NX` inside a single Redis transaction
 *   so counter initialization and TTL assignment cannot be split or reset on subsequent increments.
 * - Inspects per-command `{ result, error }` responses and fails closed when `AEGIS_REQUIRE_DISTRIBUTED_RATE_LIMIT=true`
 *   and Redis is unreachable, times out, or returns a partial command error.
 */
import type { NextRequest } from 'next/server';
import { logStructuredEvent } from './observability';
import { checkRateLimit, resolveTrustedClientIp } from './security-guard';

export type RateLimiterMode =
  | 'UPSTASH_REDIS'
  | 'MEMORY_SINGLE_INSTANCE'
  | 'MISCONFIGURED_FAIL_CLOSED';

export interface DistributedRateLimitResult {
  allowed: boolean;
  remaining: number;
  modeUsed: RateLimiterMode;
  degraded?: boolean;
  limitScope?: 'IP' | 'SESSION';
  retryAfterSeconds?: number;
}

export type PublicAiRouteKind = 'INVESTIGATE' | 'COPILOT' | 'SANDBOX' | 'VISION_OCR';

export interface PublicAiRouteLimits {
  sessionMaxPerMinute: number;
  ipBurstMaxPerMinute: number;
}

const parsePositiveIntEnv = (
  raw: string | undefined,
  fallback: number,
  min: number,
  max: number
): number => {
  if (!raw) return fallback;
  const parsed = Number.parseInt(raw.trim(), 10);
  if (!Number.isFinite(parsed) || parsed < min) return fallback;
  return Math.min(parsed, max);
};

/**
 * Resolves layered per-session and shared-NAT per-IP burst limits for public AI endpoints.
 * Keeping per-session caps lower than the shared-NAT per-IP burst prevents a single heavy
 * session behind conference/judge Wi-Fi NAT from starving other valid judges on the same IP.
 */
export const resolvePublicAiRouteLimits = (kind: PublicAiRouteKind): PublicAiRouteLimits => {
  let sessionMaxPerMinute: number;
  switch (kind) {
    case 'VISION_OCR':
      sessionMaxPerMinute = parsePositiveIntEnv(process.env.AI_OCR_RATE_LIMIT_PER_MIN, 6, 1, 60);
      break;
    case 'SANDBOX':
      sessionMaxPerMinute = parsePositiveIntEnv(process.env.AI_SANDBOX_RATE_LIMIT_PER_MIN, 8, 1, 60);
      break;
    case 'COPILOT':
    case 'INVESTIGATE':
    default:
      sessionMaxPerMinute = parsePositiveIntEnv(process.env.AI_RATE_LIMIT_PER_MIN, 12, 1, 120);
      break;
  }

  const configuredIpBurst = parsePositiveIntEnv(
    process.env.AI_IP_BURST_LIMIT_PER_MIN,
    36,
    1,
    300
  );
  return {
    sessionMaxPerMinute,
    ipBurstMaxPerMinute: Math.max(sessionMaxPerMinute, configuredIpBurst),
  };
};

export interface UpstashCommandEntry {
  result?: unknown;
  error?: string;
}

export type AtomicWindowIncrementOutcome =
  | {
      ok: true;
      count: number;
      ttlInitialized: boolean;
    }
  | {
      ok: false;
      errorCode: 'HTTP_ERROR' | 'COMMAND_ERROR' | 'MALFORMED_RESPONSE' | 'NETWORK_TIMEOUT';
    };

export const getUpstashConfig = (): { url: string; token: string } | null => {
  const url = process.env.UPSTASH_REDIS_REST_URL?.trim();
  const token = process.env.UPSTASH_REDIS_REST_TOKEN?.trim();
  if (!url || !token) return null;
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return null;
    return { url: url.replace(/\/+$/, ''), token };
  } catch {
    return null;
  }
};

export const isStrictDistributedRateLimitRequired = (): boolean => {
  return (
    process.env.AEGIS_REQUIRE_DISTRIBUTED_RATE_LIMIT === 'true' ||
    process.env.AEGIS_PRODUCTION_STRICT_READINESS === 'true'
  );
};

export const getDistributedRateLimiterMode = (): RateLimiterMode => {
  if (getUpstashConfig()) return 'UPSTASH_REDIS';
  if (isStrictDistributedRateLimitRequired()) {
    return 'MISCONFIGURED_FAIL_CLOSED';
  }
  return 'MEMORY_SINGLE_INSTANCE';
};

export const pingDistributedRateLimiter = async (): Promise<{
  mode: RateLimiterMode;
  ok: boolean;
  latencyMs: number;
  errorCode?: string;
}> => {
  const mode = getDistributedRateLimiterMode();
  if (mode === 'MISCONFIGURED_FAIL_CLOSED') {
    return { mode, ok: false, latencyMs: 0, errorCode: 'MISSING_UPSTASH_CREDENTIALS' };
  }
  const cfg = getUpstashConfig();
  if (!cfg) {
    return { mode: 'MEMORY_SINGLE_INSTANCE', ok: true, latencyMs: 0 };
  }

  const start = performance.now();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 2000);
  try {
    const res = await fetch(`${cfg.url}/ping`, {
      method: 'GET',
      headers: { Authorization: `Bearer ${cfg.token}` },
      signal: controller.signal,
    });
    return {
      mode: 'UPSTASH_REDIS',
      ok: res.ok,
      latencyMs: Math.round(performance.now() - start),
      errorCode: res.ok ? undefined : `REDIS_HTTP_${res.status}`,
    };
  } catch {
    return {
      mode: 'UPSTASH_REDIS',
      ok: false,
      latencyMs: Math.round(performance.now() - start),
      errorCode: 'REDIS_UNREACHABLE',
    };
  } finally {
    clearTimeout(timer);
  }
};

/**
 * Atomically increments a rate-limit window key and sets its TTL only when no TTL exists (`NX`)
 * using Upstash Redis REST `/multi-exec` (`MULTI`/`EXEC` transaction).
 */
export const executeAtomicRedisWindowIncrement = async (params: {
  cfg: { url: string; token: string };
  key: string;
  windowMs: number;
  timeoutMs?: number;
}): Promise<AtomicWindowIncrementOutcome> => {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), params.timeoutMs ?? 2500);
  try {
    const res = await fetch(`${params.cfg.url}/multi-exec`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${params.cfg.token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify([
        ['INCR', params.key],
        ['PEXPIRE', params.key, params.windowMs, 'NX'],
      ]),
      signal: controller.signal,
    });

    if (!res.ok) {
      return { ok: false, errorCode: 'HTTP_ERROR' };
    }

    const payload = (await res.json()) as unknown;
    if (!Array.isArray(payload) || payload.length < 2) {
      if (
        payload &&
        typeof payload === 'object' &&
        typeof (payload as { error?: unknown }).error === 'string'
      ) {
        return { ok: false, errorCode: 'COMMAND_ERROR' };
      }
      return { ok: false, errorCode: 'MALFORMED_RESPONSE' };
    }

    const incrEntry = payload[0] as UpstashCommandEntry | undefined;
    const pexpireEntry = payload[1] as UpstashCommandEntry | undefined;

    if (
      !incrEntry ||
      !pexpireEntry ||
      typeof incrEntry.error === 'string' ||
      typeof pexpireEntry.error === 'string'
    ) {
      return { ok: false, errorCode: 'COMMAND_ERROR' };
    }

    const count = Number(incrEntry.result);
    const pexpireFlag = Number(pexpireEntry.result);

    if (
      !Number.isInteger(count) ||
      count < 1 ||
      (pexpireFlag !== 0 && pexpireFlag !== 1)
    ) {
      return { ok: false, errorCode: 'MALFORMED_RESPONSE' };
    }

    return {
      ok: true,
      count,
      ttlInitialized: pexpireFlag === 1,
    };
  } catch {
    return { ok: false, errorCode: 'NETWORK_TIMEOUT' };
  } finally {
    clearTimeout(timer);
  }
};

const handleRedisDegradation = (params: {
  routeTag: string;
  ip: string;
  sessionId?: string;
  safeIpMax: number;
  safeSessionMax: number;
  requireDistributed: boolean;
  criticalMutation?: boolean;
  errorCode: string;
}): DistributedRateLimitResult => {
  const mustFailClosed = params.requireDistributed || Boolean(params.criticalMutation && params.requireDistributed);
  logStructuredEvent({
    level: mustFailClosed ? 'ERROR' : 'WARN',
    route: params.routeTag,
    action: 'REDIS_RATE_LIMIT_DEGRADED',
    status: mustFailClosed ? 'FAIL_CLOSED' : 'FALLBACK_MEMORY',
    errorCode: params.errorCode,
  });

  if (mustFailClosed) {
    return {
      allowed: false,
      remaining: 0,
      modeUsed: 'UPSTASH_REDIS',
      degraded: true,
      retryAfterSeconds: 30,
    };
  }

  let sidRemaining: number | null = null;
  if (params.sessionId) {
    const memSid = checkRateLimit(`${params.routeTag}:sid:${params.sessionId}`, params.safeSessionMax);
    if (!memSid.allowed) {
      return {
        allowed: false,
        remaining: 0,
        modeUsed: 'MEMORY_SINGLE_INSTANCE',
        degraded: true,
        limitScope: 'SESSION',
        retryAfterSeconds: 60,
      };
    }
    sidRemaining = memSid.remaining;
  }

  const memIp = checkRateLimit(`${params.routeTag}:ip:${params.ip}`, params.safeIpMax);
  if (!memIp.allowed) {
    return {
      allowed: false,
      remaining: 0,
      modeUsed: 'MEMORY_SINGLE_INSTANCE',
      degraded: true,
      limitScope: 'IP',
      retryAfterSeconds: 60,
    };
  }
  return {
    allowed: true,
    remaining: sidRemaining === null ? memIp.remaining : Math.min(memIp.remaining, sidRemaining),
    modeUsed: 'MEMORY_SINGLE_INSTANCE',
    degraded: true,
  };
};

export const enforceDistributedRouteRateLimit = async (
  req: NextRequest,
  routeTag: string,
  maxPerMinute: number,
  options?: {
    sessionId?: string;
    sessionMaxPerMinute?: number;
    criticalMutation?: boolean;
  }
): Promise<DistributedRateLimitResult> => {
  const ip = resolveTrustedClientIp(req);
  const safeIpMax = Number.isFinite(maxPerMinute) && maxPerMinute > 0 ? Math.floor(maxPerMinute) : 30;
  const safeSessionMax =
    typeof options?.sessionMaxPerMinute === 'number' &&
    Number.isFinite(options.sessionMaxPerMinute) &&
    options.sessionMaxPerMinute > 0
      ? Math.floor(options.sessionMaxPerMinute)
      : safeIpMax;
  const requireDistributed = isStrictDistributedRateLimitRequired();
  const cfg = getUpstashConfig();

  if (!cfg) {
    if (requireDistributed) {
      logStructuredEvent({
        level: 'ERROR',
        route: routeTag,
        action: 'DISTRIBUTED_RATE_LIMIT_MISCONFIGURED',
        status: 'REJECTED',
        errorCode: 'MISCONFIGURED_FAIL_CLOSED',
      });
      return {
        allowed: false,
        remaining: 0,
        modeUsed: 'MISCONFIGURED_FAIL_CLOSED',
        retryAfterSeconds: 30,
      };
    }

    // Check verified per-session cap FIRST so one heavy session behind shared NAT cannot starve other judges.
    let sidRemaining: number | null = null;
    if (options?.sessionId) {
      const sidRes = checkRateLimit(`${routeTag}:sid:${options.sessionId}`, safeSessionMax);
      if (!sidRes.allowed) {
        return {
          allowed: false,
          remaining: 0,
          modeUsed: 'MEMORY_SINGLE_INSTANCE',
          limitScope: 'SESSION',
          retryAfterSeconds: 60,
        };
      }
      sidRemaining = sidRes.remaining;
    }

    const ipRes = checkRateLimit(`${routeTag}:ip:${ip}`, safeIpMax);
    if (!ipRes.allowed) {
      return {
        allowed: false,
        remaining: 0,
        modeUsed: 'MEMORY_SINGLE_INSTANCE',
        limitScope: 'IP',
        retryAfterSeconds: 60,
      };
    }
    return {
      allowed: true,
      remaining: sidRemaining === null ? ipRes.remaining : Math.min(ipRes.remaining, sidRemaining),
      modeUsed: 'MEMORY_SINGLE_INSTANCE',
    };
  }

  const windowBucket = Math.floor(Date.now() / 60_000);
  const retryAfterSeconds = Math.max(1, 60 - Math.floor((Date.now() % 60_000) / 1000));

  // Shared-NAT protection: check verified per-session bucket BEFORE incrementing the shared IP bucket.
  let sidRemaining: number | null = null;
  if (options?.sessionId) {
    const sidKey = `aegis:rl:${routeTag}:sid:${options.sessionId}:${windowBucket}`;
    const sidOutcome = await executeAtomicRedisWindowIncrement({
      cfg,
      key: sidKey,
      windowMs: 65_000,
    });
    if (!sidOutcome.ok) {
      return handleRedisDegradation({
        routeTag,
        ip,
        sessionId: options.sessionId,
        safeIpMax,
        safeSessionMax,
        requireDistributed,
        criticalMutation: options.criticalMutation,
        errorCode: `REDIS_SID_${sidOutcome.errorCode}`,
      });
    }
    if (sidOutcome.count > safeSessionMax) {
      return {
        allowed: false,
        remaining: 0,
        modeUsed: 'UPSTASH_REDIS',
        limitScope: 'SESSION',
        retryAfterSeconds,
      };
    }
    sidRemaining = Math.max(0, safeSessionMax - sidOutcome.count);
  }

  const ipKey = `aegis:rl:${routeTag}:ip:${ip}:${windowBucket}`;
  const ipOutcome = await executeAtomicRedisWindowIncrement({
    cfg,
    key: ipKey,
    windowMs: 65_000,
  });

  if (!ipOutcome.ok) {
    return handleRedisDegradation({
      routeTag,
      ip,
      sessionId: options?.sessionId,
      safeIpMax,
      safeSessionMax,
      requireDistributed,
      criticalMutation: options?.criticalMutation,
      errorCode: `REDIS_IP_${ipOutcome.errorCode}`,
    });
  }

  if (ipOutcome.count > safeIpMax) {
    return {
      allowed: false,
      remaining: 0,
      modeUsed: 'UPSTASH_REDIS',
      limitScope: 'IP',
      retryAfterSeconds,
    };
  }

  const ipRemaining = Math.max(0, safeIpMax - ipOutcome.count);
  return {
    allowed: true,
    remaining: sidRemaining === null ? ipRemaining : Math.min(ipRemaining, sidRemaining),
    modeUsed: 'UPSTASH_REDIS',
  };
};
