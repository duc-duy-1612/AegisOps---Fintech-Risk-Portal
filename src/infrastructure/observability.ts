/**
 * Structured Redacted Observability Logger & Request Tracing Utility (Wave 4.1).
 * Automatically masks secrets, tokens, cookies, base64 images, and sensitive identifiers
 * before emitting single-line JSON logs for Vercel Functions & CI diagnostics.
 */
import { randomUUID } from 'node:crypto';

export type LogLevel = 'INFO' | 'WARN' | 'ERROR';

export interface StructuredLogEntry {
  timestamp: string;
  level: LogLevel;
  requestId: string;
  route: string;
  action: string;
  status: string;
  durationMs?: number;
  errorCode?: string;
  environment: string;
  metadata?: Record<string, unknown>;
}

const SENSITIVE_KEY_PATTERN =
  /secret|token|key|cookie|authorization|password|imagedataurl|base64|connectionstring|database_url/i;

export const redactSensitiveMetadata = (value: unknown, depth = 0): unknown => {
  if (depth > 4) return '[TRUNCATED]';
  if (value === null || value === undefined) return value;
  if (typeof value === 'string') {
    if (value.startsWith('data:image/')) {
      return `[REDACTED_IMAGE_DATA_URL:${value.length}_CHARS]`;
    }
    if (/postgres(ql)?:\/\/|rediss?:\/\//i.test(value)) {
      return '[REDACTED_CONNECTION_URI]';
    }
    // Mask long raw digit sequences that resemble bank accounts / phone numbers (10-19 digits)
    return value.replace(/\b(\d{3})\d{4,12}(\d{3})\b/g, '$1****$2').slice(0, 300);
  }
  if (typeof value === 'number' || typeof value === 'boolean') return value;
  if (Array.isArray(value)) {
    return value.slice(0, 20).map((item) => redactSensitiveMetadata(item, depth + 1));
  }
  if (typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (SENSITIVE_KEY_PATTERN.test(k)) {
        out[k] = '[REDACTED]';
      } else {
        out[k] = redactSensitiveMetadata(v, depth + 1);
      }
    }
    return out;
  }
  return String(value);
};

export const generateRequestTraceId = (): string => `req-${randomUUID().slice(0, 12)}`;

export const logStructuredEvent = (params: {
  level?: LogLevel;
  requestId?: string;
  route: string;
  action: string;
  status: string;
  durationMs?: number;
  errorCode?: string;
  metadata?: Record<string, unknown>;
}): StructuredLogEntry => {
  const entry: StructuredLogEntry = {
    timestamp: new Date().toISOString(),
    level: params.level ?? 'INFO',
    requestId: params.requestId ?? generateRequestTraceId(),
    route: params.route,
    action: params.action,
    status: params.status,
    durationMs: params.durationMs !== undefined ? Math.round(params.durationMs) : undefined,
    errorCode: params.errorCode,
    environment: process.env.VERCEL_ENV || process.env.NODE_ENV || 'development',
    metadata: params.metadata
      ? (redactSensitiveMetadata(params.metadata) as Record<string, unknown>)
      : undefined,
  };

  if (process.env.NODE_ENV !== 'test') {
    const serialized = JSON.stringify(entry);
    if (entry.level === 'ERROR') {
      console.error(serialized);
    } else if (entry.level === 'WARN') {
      console.warn(serialized);
    } else {
      console.info(serialized);
    }
  }
  return entry;
};
