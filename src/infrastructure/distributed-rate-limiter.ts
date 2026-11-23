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
}

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
  safeMax: number;
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
    return { allowed: false, remaining: 0, modeUsed: 'UPSTASH_REDIS', degraded: true };
  }

  const memIp = checkRateLimit(`${params.routeTag}:ip:${params.ip}`, params.safeMax);
  if (!memIp.allowed) {
    return { allowed: false, remaining: 0, modeUsed: 'MEMORY_SINGLE_INSTANCE', degraded: true };
  }
  if (params.sessionId) {
    const memSid = checkRateLimit(`${params.routeTag}:sid:${params.sessionId}`, params.safeMax);
    return {
      allowed: memSid.allowed,
      remaining: Math.min(memIp.remaining, memSid.remaining),
      modeUsed: 'MEMORY_SINGLE_INSTANCE',
      degraded: true,
    };
  }
  return {
    allowed: memIp.allowed,
    remaining: memIp.remaining,
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
    criticalMutation?: boolean;
  }
): Promise<DistributedRateLimitResult> => {
  const ip = resolveTrustedClientIp(req);
  const safeMax = Number.isFinite(maxPerMinute) && maxPerMinute > 0 ? Math.floor(maxPerMinute) : 30;
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
      return { allowed: false, remaining: 0, modeUsed: 'MISCONFIGURED_FAIL_CLOSED' };
    }

    const ipRes = checkRateLimit(`${routeTag}:ip:${ip}`, safeMax);
    if (!ipRes.allowed) {
      return { allowed: false, remaining: 0, modeUsed: 'MEMORY_SINGLE_INSTANCE' };
    }
    if (options?.sessionId) {
      const sidRes = checkRateLimit(`${routeTag}:sid:${options.sessionId}`, safeMax);
      return {
        allowed: sidRes.allowed,
        remaining: Math.min(ipRes.remaining, sidRes.remaining),
        modeUsed: 'MEMORY_SINGLE_INSTANCE',
      };
    }
    return { allowed: true, remaining: ipRes.remaining, modeUsed: 'MEMORY_SINGLE_INSTANCE' };
  }

  const windowBucket = Math.floor(Date.now() / 60_000);
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
      safeMax,
      requireDistributed,
      criticalMutation: options?.criticalMutation,
      errorCode: `REDIS_IP_${ipOutcome.errorCode}`,
    });
  }

  if (ipOutcome.count > safeMax) {
    return { allowed: false, remaining: 0, modeUsed: 'UPSTASH_REDIS' };
  }

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
        safeMax,
        requireDistributed,
        criticalMutation: options.criticalMutation,
        errorCode: `REDIS_SID_${sidOutcome.errorCode}`,
      });
    }
    if (sidOutcome.count > safeMax) {
      return { allowed: false, remaining: 0, modeUsed: 'UPSTASH_REDIS' };
    }
    const effectiveRemaining = Math.min(safeMax - ipOutcome.count, safeMax - sidOutcome.count);
    return { allowed: true, remaining: Math.max(0, effectiveRemaining), modeUsed: 'UPSTASH_REDIS' };
  }

  return { allowed: true, remaining: Math.max(0, safeMax - ipOutcome.count), modeUsed: 'UPSTASH_REDIS' };
};
