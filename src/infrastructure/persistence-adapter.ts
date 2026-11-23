/**
 * Wave 4.1.1 Authoritative Persistence Abstraction & PostgreSQL ACID Adapter.
 *
 * - Decouples session revisions, HITL feedback revocations, double-entry ledger postings,
 *   and Clawback receipts from volatile serverless instance memory (`Map`).
 * - Serverless-safe connection strategy: separates runtime pooled `DATABASE_URL` (`PG_POOL_MAX=1`
 *   default on serverless with `allowExitOnIdle: true`) from administrative/migration `DIRECT_URL`.
 * - Full ACID lifecycle (`BEGIN` -> `SELECT ... FOR UPDATE` -> CAS & expiry check -> guarded `ON CONFLICT`
 *   with `WHERE state_revision = $7` -> monotonic HITL sync -> ledger/clawback unique-constraint guard -> `COMMIT`/`ROLLBACK`).
 */
import { Pool, type PoolClient, type PoolConfig, type QueryResult } from 'pg';
import type { ClawbackReceiptRecord, SessionDeltaSnapshot, Transaction, TransactionStatus } from '@/domain/types';

/**
 * Computes cumulative recovered clawback amount per original settled transaction ID
 * using the exact domain rule from `workspace-store.ts` so normalized PostgreSQL
 * `aegis_ledger_transactions.status` transitions monotonically to `REVERSED` upon full clawback.
 */
export const buildReversedAmountByTxId = (
  clawbackReceipts: readonly ClawbackReceiptRecord[] = []
): Map<string, number> => {
  const reversedAmountByTxId = new Map<string, number>();
  for (const receipt of clawbackReceipts) {
    if (receipt.recoveredAmountVnd <= 0 || receipt.txIds.length === 0) continue;
    if (receipt.txIds.length === 1) {
      const origId = receipt.txIds[0]!;
      reversedAmountByTxId.set(
        origId,
        (reversedAmountByTxId.get(origId) ?? 0) + Math.round(receipt.recoveredAmountVnd)
      );
    } else if (receipt.recoveryStatus === 'RECOVERED' && (receipt.missingAmountVnd ?? 0) === 0) {
      for (const origId of receipt.txIds) {
        reversedAmountByTxId.set(origId, Number.MAX_SAFE_INTEGER);
      }
    }
  }
  return reversedAmountByTxId;
};

export const resolveEffectivePersistedTransactionStatus = (
  tx: Transaction,
  reversedAmountByTxId: ReadonlyMap<string, number>
): TransactionStatus => {
  if (
    tx.txKind !== 'CLAWBACK_REVERSAL' &&
    (tx.status === 'COMPLETED' || tx.status === 'SETTLED')
  ) {
    const reversedTotal = reversedAmountByTxId.get(tx.id) ?? 0;
    if (reversedTotal >= Math.round(tx.amountVnd)) {
      return 'REVERSED';
    }
  }
  return tx.status;
};

export class ConcurrentStateConflictError extends Error {
  constructor(message = 'Xung đột đồng thời: phiên dữ liệu vừa được cập nhật bởi yêu cầu khác. Vui lòng đồng bộ lại.') {
    super(message);
    this.name = 'ConcurrentStateConflictError';
  }
}

export class PersistenceUnavailableError extends Error {
  constructor(message = 'Cơ sở dữ liệu lưu trữ dùng chung (PostgreSQL) chưa sẵn sàng hoặc thiếu cấu hình DATABASE_URL.') {
    super(message);
    this.name = 'PersistenceUnavailableError';
  }
}

export type PostgresTlsErrorReasonCode =
  | 'INVALID_DATABASE_URL'
  | 'MISSING_PRODUCTION_SSL_MODE'
  | 'DISALLOWED_SSL_MODE'
  | 'INSECURE_SSL_OPTION'
  | 'DISALLOWED_CHANNEL_BINDING';

export class PostgresTlsConfigurationError extends PersistenceUnavailableError {
  public readonly reasonCode: PostgresTlsErrorReasonCode;

  constructor(reasonCode: PostgresTlsErrorReasonCode, message: string) {
    super(message);
    this.name = 'PostgresTlsConfigurationError';
    this.reasonCode = reasonCode;
  }
}

export interface PostgresPoolConfigOptions {
  strictProductionTls?: boolean;
  poolMax?: number;
  sslOverride?: false | { rejectUnauthorized?: boolean };
}

export interface ResolvedPostgresPoolConfigResult {
  poolConfig: PoolConfig;
  tlsEnabled: boolean;
  rejectUnauthorized: boolean | null;
  enableChannelBinding: boolean;
  strictProductionTls: boolean;
  effectiveSslMode: string;
}

const VALID_PG_SSL_MODES = new Set([
  'disable',
  'allow',
  'prefer',
  'require',
  'verify-ca',
  'verify-full',
  'no-verify',
]);

const VALID_CHANNEL_BINDING_MODES = new Set(['require', 'prefer', 'disable']);

const SSL_QUERY_PARAM_KEYS = new Set([
  'ssl',
  'sslmode',
  'uselibpqcompat',
  'channel_binding',
]);

export const isProductionStrictTlsRequired = (
  env: NodeJS.ProcessEnv = process.env
): boolean =>
  env.NODE_ENV === 'production' ||
  env.VERCEL === '1' ||
  env.VERCEL_ENV === 'production' ||
  env.AEGIS_PRODUCTION_STRICT_READINESS === 'true' ||
  env.AEGIS_REQUIRE_SHARED_PERSISTENCE === 'true';

/**
 * Validates and normalizes a PostgreSQL connection string for `pg@8.23.1` + `pg-connection-string@2.14.1`.
 *
 * Security invariants (Wave 4.2.1B NEON-03):
 * - In strict/production mode, requires explicit `sslmode=verify-full` and fails closed on missing,
 *   weak (`disable`, `allow`, `prefer`, `require`, `verify-ca`, `no-verify`), unsupported SSL modes,
 *   `uselibpqcompat=true`, `channel_binding=disable`, or explicit `rejectUnauthorized: false`.
 * - Strips URL SSL query params from the normalized string passed to `Pool` after validation so
 *   `pg/lib/connection-parameters.js` (`Object.assign({}, config, parse(connectionString))`) cannot
 *   silently overwrite explicit `{ rejectUnauthorized: true }` with `{}` or an insecure object.
 * - Explicitly sets `enableChannelBinding: true` on `PoolConfig` because `pg@8.23.1` reads
 *   `config.enableChannelBinding` on `Client` rather than URL `channel_binding=require`.
 * - Never embeds credentials or full connection strings in thrown errors.
 */
export const buildPostgresPoolConfig = (
  connectionString: string,
  options?: PostgresPoolConfigOptions
): ResolvedPostgresPoolConfigResult => {
  const strict = options?.strictProductionTls ?? isProductionStrictTlsRequired();
  const trimmed = (connectionString ?? '').trim();

  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw new PostgresTlsConfigurationError(
      'INVALID_DATABASE_URL',
      'Cấu hình DATABASE_URL PostgreSQL không hợp lệ.'
    );
  }

  if (
    (parsed.protocol !== 'postgres:' && parsed.protocol !== 'postgresql:') ||
    !parsed.hostname
  ) {
    throw new PostgresTlsConfigurationError(
      'INVALID_DATABASE_URL',
      'DATABASE_URL phải sử dụng giao thức postgres:// hoặc postgresql:// với hostname hợp lệ.'
    );
  }

  const normalizedParams = new Map<string, string>();
  for (const [k, v] of parsed.searchParams.entries()) {
    normalizedParams.set(k.trim().toLowerCase(), v.trim().toLowerCase());
  }

  const sslMode = normalizedParams.get('sslmode');
  const sslParam = normalizedParams.get('ssl');
  const useLibpqCompat = normalizedParams.get('uselibpqcompat');
  const channelBinding = normalizedParams.get('channel_binding');
  const hostLower = parsed.hostname.toLowerCase();
  const isLocalHost =
    hostLower === 'localhost' || hostLower === '127.0.0.1' || hostLower === '::1';

  if (sslMode !== undefined && !VALID_PG_SSL_MODES.has(sslMode)) {
    throw new PostgresTlsConfigurationError(
      'DISALLOWED_SSL_MODE',
      'Tham số sslmode trong DATABASE_URL không được hỗ trợ.'
    );
  }

  if (channelBinding !== undefined && !VALID_CHANNEL_BINDING_MODES.has(channelBinding)) {
    throw new PostgresTlsConfigurationError(
      'DISALLOWED_CHANNEL_BINDING',
      'Tham số channel_binding trong DATABASE_URL không hợp lệ (chỉ chấp nhận require, prefer, disable).'
    );
  }

  if (
    options?.sslOverride === false ||
    (options?.sslOverride && options.sslOverride.rejectUnauthorized === false)
  ) {
    if (strict || !isLocalHost) {
      throw new PostgresTlsConfigurationError(
        'INSECURE_SSL_OPTION',
        'Từ chối cấu hình TLS không an toàn (rejectUnauthorized=false hoặc tắt SSL).'
      );
    }
  }

  if (
    useLibpqCompat === 'true' ||
    sslParam === 'no-verify' ||
    sslMode === 'no-verify'
  ) {
    throw new PostgresTlsConfigurationError(
      'INSECURE_SSL_OPTION',
      'Từ chối tham số làm suy yếu xác thực chứng chỉ TLS PostgreSQL (no-verify / uselibpqcompat).'
    );
  }

  let tlsEnabled = true;
  let enableChannelBinding = false;
  let effectiveSslMode = 'verify-full';

  if (strict) {
    if (sslParam === '0' || sslParam === 'false') {
      throw new PostgresTlsConfigurationError(
        'INSECURE_SSL_OPTION',
        'Môi trường production không cho phép tắt SSL (ssl=0/false).'
      );
    }
    if (!sslMode) {
      throw new PostgresTlsConfigurationError(
        'MISSING_PRODUCTION_SSL_MODE',
        'Môi trường production yêu cầu khai báo rõ sslmode=verify-full trong DATABASE_URL.'
      );
    }
    if (sslMode !== 'verify-full') {
      throw new PostgresTlsConfigurationError(
        'DISALLOWED_SSL_MODE',
        'Môi trường production chỉ chấp nhận sslmode=verify-full để xác thực đầy đủ chứng chỉ CA và hostname.'
      );
    }
    if (channelBinding === 'disable') {
      throw new PostgresTlsConfigurationError(
        'DISALLOWED_CHANNEL_BINDING',
        'Môi trường production không cho phép channel_binding=disable.'
      );
    }
    tlsEnabled = true;
    enableChannelBinding = true;
    effectiveSslMode = 'verify-full';
  } else if (isLocalHost) {
    const localWantsTls =
      sslMode === 'verify-full' ||
      sslMode === 'require' ||
      sslMode === 'verify-ca' ||
      sslMode === 'prefer' ||
      sslParam === 'true' ||
      sslParam === '1';

    if (localWantsTls) {
      tlsEnabled = true;
      enableChannelBinding = channelBinding === 'require' || channelBinding === 'prefer';
      effectiveSslMode = sslMode ?? 'verify-full';
    } else {
      tlsEnabled = false;
      enableChannelBinding = false;
      effectiveSslMode = 'disable';
    }
  } else {
    // Non-local remote host in non-strict development mode still enforces verified TLS (fail-closed on disable/missing)
    if (sslParam === '0' || sslParam === 'false' || sslMode === 'disable' || sslMode === 'allow') {
      throw new PostgresTlsConfigurationError(
        'DISALLOWED_SSL_MODE',
        'Kết nối PostgreSQL từ xa không được phép tắt TLS.'
      );
    }
    if (!sslMode && sslParam !== 'true' && sslParam !== '1') {
      throw new PostgresTlsConfigurationError(
        'MISSING_PRODUCTION_SSL_MODE',
        'Kết nối PostgreSQL từ xa yêu cầu khai báo sslmode=verify-full (hoặc sslmode=require ở chế độ dev).'
      );
    }
    tlsEnabled = true;
    enableChannelBinding = channelBinding === 'require' || channelBinding === 'prefer';
    effectiveSslMode = sslMode ?? 'verify-full';
  }

  // Strip URL-level SSL/channel_binding query params after strict validation so pg-connection-string
  // cannot replace our explicit `{ rejectUnauthorized: true }` or emit legacy sslmode deprecation warnings.
  const normalizedUrl = new URL(parsed.toString());
  for (const existingKey of Array.from(normalizedUrl.searchParams.keys())) {
    if (SSL_QUERY_PARAM_KEYS.has(existingKey.trim().toLowerCase())) {
      normalizedUrl.searchParams.delete(existingKey);
    }
  }

  const poolMax = options?.poolMax ?? resolveServerlessPoolMax();
  const poolConfig: PoolConfig = {
    connectionString: normalizedUrl.toString(),
    max: poolMax,
    idleTimeoutMillis: 10_000,
    connectionTimeoutMillis: 4_000,
    allowExitOnIdle: true,
    ssl: tlsEnabled ? { rejectUnauthorized: true } : undefined,
    enableChannelBinding,
  };

  return {
    poolConfig,
    tlsEnabled,
    rejectUnauthorized: tlsEnabled ? true : null,
    enableChannelBinding,
    strictProductionTls: strict,
    effectiveSslMode,
  };
};

export class SessionRevokedError extends Error {
  constructor(message = 'Phiên làm việc đã bị thu hồi hoặc hết hạn trên máy chủ.') {
    super(message);
    this.name = 'SessionRevokedError';
  }
}

export interface StoredSessionEnvelope {
  sessionId: string;
  principalId: string;
  status: 'ACTIVE' | 'REVOKED' | 'EXPIRED';
  delta: SessionDeltaSnapshot;
  expiresAt: string;
  revokedAt?: string | null;
}

export interface PersistenceHealthPing {
  mode: 'POSTGRES' | 'MEMORY' | 'MISCONFIGURED_FAIL_CLOSED';
  ok: boolean;
  latencyMs: number;
  errorCode?: string;
}

export interface PgQueryableClient {
  query: (text: string, values?: unknown[]) => Promise<Pick<QueryResult, 'rows' | 'rowCount'>>;
  release?: () => void;
}

export interface PgQueryablePool {
  query: (text: string, values?: unknown[]) => Promise<Pick<QueryResult, 'rows' | 'rowCount'>>;
  connect: () => Promise<PgQueryableClient>;
  end?: () => Promise<void>;
}

export interface WorkspacePersistenceAdapter {
  readonly mode: 'POSTGRES' | 'MEMORY' | 'MISCONFIGURED_FAIL_CLOSED';
  loadSession(sessionId: string): Promise<StoredSessionEnvelope | null>;
  commitSession(params: {
    sessionId: string;
    principalId: string;
    expectedRevision: number;
    nextDelta: SessionDeltaSnapshot;
    expiresAtIso: string;
  }): Promise<SessionDeltaSnapshot>;
  revokeSession(sessionId: string): Promise<void>;
  isSessionRevoked(sessionId: string): Promise<boolean>;
  ping(): Promise<PersistenceHealthPing>;
  close?(): Promise<void>;
}

export const isValidPostgresConnectionUrl = (raw?: string | null): boolean => {
  if (!raw) return false;
  const trimmed = raw.trim();
  if (!trimmed) return false;
  try {
    const parsed = new URL(trimmed);
    return (parsed.protocol === 'postgres:' || parsed.protocol === 'postgresql:') && Boolean(parsed.hostname);
  } catch {
    return false;
  }
};

export const getPostgresMigrationConnectionUrl = (): string | null => {
  const direct = process.env.DIRECT_URL?.trim();
  if (isValidPostgresConnectionUrl(direct)) return direct!;
  const pooled = process.env.DATABASE_URL?.trim();
  if (isValidPostgresConnectionUrl(pooled)) return pooled!;
  return null;
};

export const resolveServerlessPoolMax = (): number => {
  const raw = Number(process.env.PG_POOL_MAX);
  if (Number.isInteger(raw) && raw >= 1 && raw <= 10) {
    return raw;
  }
  const isServerless = Boolean(process.env.VERCEL || process.env.AWS_LAMBDA_FUNCTION_NAME || process.env.NODE_ENV === 'production');
  return isServerless ? 1 : 2;
};

export const evaluateServerlessPoolSizing = (params?: {
  concurrentInstances?: number;
  poolMaxPerInstance?: number;
  connectionBudgetLimit?: number;
}): {
  poolMaxPerInstance: number;
  concurrentInstances: number;
  projectedMaxConnections: number;
  withinBudget: boolean;
  usesPooledEndpoint: boolean;
} => {
  const poolMaxPerInstance = params?.poolMaxPerInstance ?? resolveServerlessPoolMax();
  const concurrentInstances = Math.max(1, params?.concurrentInstances ?? 40);
  const budget = Math.max(10, params?.connectionBudgetLimit ?? 100);
  const projectedMaxConnections = poolMaxPerInstance * concurrentInstances;
  const dbUrl = process.env.DATABASE_URL?.trim() ?? '';
  const usesPooledEndpoint = dbUrl.includes('-pooler.') || dbUrl.includes('pgbouncer=true');

  return {
    poolMaxPerInstance,
    concurrentInstances,
    projectedMaxConnections,
    withinBudget: projectedMaxConnections <= budget,
    usesPooledEndpoint,
  };
};

export class InMemoryPersistenceAdapter implements WorkspacePersistenceAdapter {
  public readonly mode = 'MEMORY' as const;
  private readonly store = new Map<string, StoredSessionEnvelope>();
  private readonly revokedIds = new Set<string>();

  async loadSession(sessionId: string): Promise<StoredSessionEnvelope | null> {
    if (this.revokedIds.has(sessionId)) {
      const env = this.store.get(sessionId);
      return env ? { ...env, status: 'REVOKED' } : null;
    }
    const existing = this.store.get(sessionId);
    if (!existing) return null;
    const expMs = Date.parse(existing.expiresAt);
    if (existing.status === 'ACTIVE' && Number.isFinite(expMs) && expMs <= Date.now()) {
      return { ...existing, status: 'EXPIRED' };
    }
    return existing;
  }

  async commitSession(params: {
    sessionId: string;
    principalId: string;
    expectedRevision: number;
    nextDelta: SessionDeltaSnapshot;
    expiresAtIso: string;
  }): Promise<SessionDeltaSnapshot> {
    if (this.revokedIds.has(params.sessionId)) {
      throw new SessionRevokedError();
    }
    const existing = this.store.get(params.sessionId);
    if (existing) {
      const expMs = Date.parse(existing.expiresAt);
      if (existing.status === 'REVOKED' || existing.status === 'EXPIRED' || (Number.isFinite(expMs) && expMs <= Date.now())) {
        throw new SessionRevokedError();
      }
      const currentRev = existing.delta.stateRevision ?? 0;
      if (params.expectedRevision !== currentRev) {
        throw new ConcurrentStateConflictError();
      }
      const nextRev = params.nextDelta.stateRevision ?? 0;
      if (nextRev <= currentRev) {
        throw new ConcurrentStateConflictError();
      }
    }
    this.store.set(params.sessionId, {
      sessionId: params.sessionId,
      principalId: params.principalId,
      status: 'ACTIVE',
      delta: params.nextDelta,
      expiresAt: params.expiresAtIso,
      revokedAt: null,
    });
    return params.nextDelta;
  }

  async revokeSession(sessionId: string): Promise<void> {
    this.revokedIds.add(sessionId);
    const existing = this.store.get(sessionId);
    if (existing) {
      this.store.set(sessionId, {
        ...existing,
        status: 'REVOKED',
        revokedAt: new Date().toISOString(),
      });
    }
  }

  async isSessionRevoked(sessionId: string): Promise<boolean> {
    if (this.revokedIds.has(sessionId)) return true;
    const existing = this.store.get(sessionId);
    if (!existing) return false;
    if (existing.status === 'REVOKED' || existing.status === 'EXPIRED') return true;
    const expMs = Date.parse(existing.expiresAt);
    return Number.isFinite(expMs) && expMs <= Date.now();
  }

  async ping(): Promise<PersistenceHealthPing> {
    return { mode: 'MEMORY', ok: true, latencyMs: 0 };
  }
}

export class FailClosedPersistenceAdapter implements WorkspacePersistenceAdapter {
  public readonly mode = 'MISCONFIGURED_FAIL_CLOSED' as const;
  private readonly errorCode: string;

  constructor(errorCode = 'MISSING_OR_INVALID_DATABASE_URL') {
    this.errorCode = errorCode;
  }

  async loadSession(): Promise<StoredSessionEnvelope | null> {
    throw new PersistenceUnavailableError();
  }

  async commitSession(): Promise<SessionDeltaSnapshot> {
    throw new PersistenceUnavailableError();
  }

  async revokeSession(): Promise<void> {
    throw new PersistenceUnavailableError();
  }

  async isSessionRevoked(): Promise<boolean> {
    throw new PersistenceUnavailableError();
  }

  async ping(): Promise<PersistenceHealthPing> {
    return {
      mode: 'MISCONFIGURED_FAIL_CLOSED',
      ok: false,
      latencyMs: 0,
      errorCode: this.errorCode,
    };
  }
}

export class PostgresPersistenceAdapter implements WorkspacePersistenceAdapter {
  public readonly mode = 'POSTGRES' as const;
  private readonly pool: PgQueryablePool;
  public readonly poolMax: number;
  public readonly resolvedPoolConfig?: ResolvedPostgresPoolConfigResult;

  constructor(
    connectionStringOrPool: string | PgQueryablePool,
    options?: PostgresPoolConfigOptions
  ) {
    this.poolMax = options?.poolMax ?? resolveServerlessPoolMax();
    if (typeof connectionStringOrPool === 'string') {
      const resolved = buildPostgresPoolConfig(connectionStringOrPool, {
        ...options,
        poolMax: this.poolMax,
      });
      this.resolvedPoolConfig = resolved;
      this.pool = new Pool(resolved.poolConfig) as unknown as PgQueryablePool;
    } else {
      this.pool = connectionStringOrPool;
    }
  }

  async loadSession(sessionId: string): Promise<StoredSessionEnvelope | null> {
    const res = await this.pool.query(
      `SELECT session_id, principal_id, status, delta_json, expires_at, revoked_at
       FROM aegis_workspace_sessions
       WHERE session_id = $1`,
      [sessionId]
    );
    const row = res.rows[0] as
      | {
          session_id: string;
          principal_id: string;
          status: 'ACTIVE' | 'REVOKED' | 'EXPIRED';
          delta_json: SessionDeltaSnapshot | string;
          expires_at: string | Date;
          revoked_at: string | Date | null;
        }
      | undefined;

    if (!row) return null;
    const parsedDelta =
      typeof row.delta_json === 'string'
        ? (JSON.parse(row.delta_json) as SessionDeltaSnapshot)
        : row.delta_json;
    const expiresAtIso =
      row.expires_at instanceof Date ? row.expires_at.toISOString() : String(row.expires_at);
    const effectiveStatus =
      row.status === 'ACTIVE' && Date.parse(expiresAtIso) <= Date.now() ? 'EXPIRED' : row.status;

    return {
      sessionId: row.session_id,
      principalId: row.principal_id,
      status: effectiveStatus,
      delta: parsedDelta,
      expiresAt: expiresAtIso,
      revokedAt: row.revoked_at ? String(row.revoked_at) : null,
    };
  }

  async commitSession(params: {
    sessionId: string;
    principalId: string;
    expectedRevision: number;
    nextDelta: SessionDeltaSnapshot;
    expiresAtIso: string;
  }): Promise<SessionDeltaSnapshot> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');

      const lockRes = await client.query(
        `SELECT state_revision, status, expires_at
         FROM aegis_workspace_sessions
         WHERE session_id = $1
         FOR UPDATE`,
        [params.sessionId]
      );
      const locked = lockRes.rows[0] as
        | { state_revision: number; status: string; expires_at: string | Date }
        | undefined;

      const nextRev = params.nextDelta.stateRevision ?? 0;

      if (locked) {
        const expMs = Date.parse(String(locked.expires_at));
        if (
          locked.status === 'REVOKED' ||
          locked.status === 'EXPIRED' ||
          (Number.isFinite(expMs) && expMs <= Date.now())
        ) {
          throw new SessionRevokedError();
        }
        const currentRev = Number(locked.state_revision);
        if (currentRev !== params.expectedRevision) {
          throw new ConcurrentStateConflictError(
            `Xung đột revision trên Postgres (expected=${params.expectedRevision}, db=${currentRev}).`
          );
        }
        if (nextRev <= currentRev) {
          throw new ConcurrentStateConflictError(
            `Revision kế tiếp (${nextRev}) phải lớn hơn revision hiện tại trên Postgres (${currentRev}).`
          );
        }
      } else if (params.expectedRevision !== 0) {
        throw new ConcurrentStateConflictError(
          `Không tìm thấy phiên cơ sở cho expectedRevision=${params.expectedRevision}.`
        );
      }

      const upsertRes = await client.query(
        `INSERT INTO aegis_workspace_sessions (
          session_id, principal_id, state_revision, status, delta_integrity_tag, delta_json, updated_at, expires_at
        ) VALUES ($1, $2, $3, 'ACTIVE', $4, $5::jsonb, NOW(), $6)
        ON CONFLICT (session_id) DO UPDATE SET
          principal_id = EXCLUDED.principal_id,
          state_revision = EXCLUDED.state_revision,
          delta_integrity_tag = EXCLUDED.delta_integrity_tag,
          delta_json = EXCLUDED.delta_json,
          updated_at = NOW()
        WHERE aegis_workspace_sessions.state_revision = $7
          AND aegis_workspace_sessions.status = 'ACTIVE'
        RETURNING state_revision`,
        [
          params.sessionId,
          params.principalId,
          nextRev,
          params.nextDelta.deltaIntegrityTag ?? '',
          JSON.stringify(params.nextDelta),
          params.expiresAtIso,
          params.expectedRevision,
        ]
      );

      if ((upsertRes.rowCount ?? upsertRes.rows.length) === 0) {
        throw new ConcurrentStateConflictError(
          'Xung đột ghi đồng thời khi khởi tạo hoặc cập nhật phiên trên Postgres.'
        );
      }

      // Sync normalized authoritative HITL feedback & revocation records inside same ACID transaction
      for (const hitl of params.nextDelta.hitlFeedbackMemory ?? []) {
        await client.query(
          `INSERT INTO aegis_hitl_feedback (
            feedback_id, session_id, source_alert_id, target_scope, target_fingerprint,
            context_signature, feedback_decision, status, risk_adjustment, memory_version,
            actor_principal_id, approved_by_principal_id, revoked_by_principal_id,
            created_at, expires_at, revoked_at
          ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
          ON CONFLICT (feedback_id) DO UPDATE SET
            status = EXCLUDED.status,
            memory_version = EXCLUDED.memory_version,
            approved_by_principal_id = EXCLUDED.approved_by_principal_id,
            revoked_by_principal_id = EXCLUDED.revoked_by_principal_id,
            revoked_at = EXCLUDED.revoked_at
          WHERE EXCLUDED.memory_version >= aegis_hitl_feedback.memory_version
            AND aegis_hitl_feedback.status <> 'REVOKED'`,
          [
            hitl.feedbackId,
            params.sessionId,
            hitl.sourceAlertId,
            hitl.targetScope,
            hitl.targetFingerprint,
            hitl.contextSignature,
            hitl.feedbackDecision,
            hitl.status,
            hitl.riskAdjustment,
            hitl.memoryVersion,
            hitl.actorPrincipalId,
            hitl.approvedByPrincipalId ?? null,
            hitl.revokedByPrincipalId ?? null,
            hitl.createdAt,
            hitl.expiresAt,
            hitl.revokedAt ?? null,
          ]
        );
      }

      // Sync unified ledger transactions & double-entry postings atomically.
      // NEON-02 + Wave 4.2.1B LEDGER_TX_IDENTITY_GAP hardening:
      // - Propagate monotonic SETTLED/COMPLETED -> REVERSED transitions while keeping REVERSED terminal.
      // - Same-session idempotent retries and stale SETTLED/COMPLETED snapshots against terminal REVERSED
      //   match the guarded WHERE predicate and preserve existing status (`rowCount === 1`).
      // - Cross-session `tx_id` collisions or immutable-field mismatches fail the WHERE predicate
      //   (`rowCount === 0`) and abort with `ConcurrentStateConflictError` + `ROLLBACK`.
      const reversedAmountByTxId = buildReversedAmountByTxId(params.nextDelta.clawbackReceipts);
      for (const tx of params.nextDelta.customTransactions ?? []) {
        const effectiveStatus = resolveEffectivePersistedTransactionStatus(tx, reversedAmountByTxId);
        const txRes = await client.query(
          `INSERT INTO aegis_ledger_transactions (
            tx_id, session_id, alert_id, sender_account_id, receiver_account_id,
            amount_vnd, status, idempotency_key, tx_kind, created_at
          ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
          ON CONFLICT (tx_id) DO UPDATE SET
            status = CASE
              WHEN aegis_ledger_transactions.status IN ('SETTLED', 'COMPLETED')
                AND EXCLUDED.status = 'REVERSED'
              THEN 'REVERSED'
              ELSE aegis_ledger_transactions.status
            END
          WHERE aegis_ledger_transactions.session_id = EXCLUDED.session_id
            AND aegis_ledger_transactions.alert_id = EXCLUDED.alert_id
            AND aegis_ledger_transactions.sender_account_id = EXCLUDED.sender_account_id
            AND aegis_ledger_transactions.receiver_account_id = EXCLUDED.receiver_account_id
            AND aegis_ledger_transactions.amount_vnd = EXCLUDED.amount_vnd
            AND aegis_ledger_transactions.idempotency_key IS NOT DISTINCT FROM EXCLUDED.idempotency_key
            AND aegis_ledger_transactions.tx_kind IS NOT DISTINCT FROM EXCLUDED.tx_kind
          RETURNING tx_id, status`,
          [
            tx.id,
            params.sessionId,
            tx.alertId,
            tx.senderAccountId,
            tx.receiverAccountId,
            Math.round(tx.amountVnd),
            effectiveStatus,
            tx.idempotencyKey ?? null,
            tx.txKind ?? null,
            tx.timestamp,
          ]
        );
        if ((txRes.rowCount ?? txRes.rows.length) === 0) {
          throw new ConcurrentStateConflictError(
            `Xung đột toàn vẹn giao dịch Sổ cái "${tx.id}": trùng mã giao dịch khác phiên hoặc sai lệch trường bất biến trên Postgres.`
          );
        }
      }

      for (const entry of params.nextDelta.ledgerEntries ?? []) {
        await client.query(
          `INSERT INTO aegis_ledger_entries (
            entry_id, session_id, tx_id, account_id, entry_type, amount_vnd, status, created_at
          ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
          ON CONFLICT (entry_id) DO NOTHING`,
          [
            entry.id,
            params.sessionId,
            entry.txId,
            entry.accountId,
            entry.entryType,
            Math.round(entry.amountVnd),
            entry.status,
            entry.createdAt,
          ]
        );
      }

      // NEON-01: Persist all distinct multi-victim and partial clawback receipts keyed by `clawback_id`.
      // Retries of the identical clawback operation are idempotent (returning the existing row), while
      // conflicting payloads on the same `clawback_id` (rowCount === 0) or duplicate `(session_id, idempotency_key)`
      // / `(session_id, reversal_tx_id)` (SQLSTATE 23505) abort and roll back cleanly.
      for (const claw of params.nextDelta.clawbackReceipts ?? []) {
        const normalizedIdemKey = claw.idempotencyKey?.trim() || null;
        const normalizedTxIds = Array.isArray(claw.txIds) ? claw.txIds : [];
        const clawRes = await client.query(
          `INSERT INTO aegis_clawback_receipts (
            clawback_id, session_id, alert_id, idempotency_key,
            requested_amount_vnd, recovered_amount_vnd, missing_amount_vnd,
            recovery_status, reversal_tx_id, victim_account_id,
            victim_owner_name, source_mule_account_id, original_tx_ids, executed_at
          ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::jsonb,$14)
          ON CONFLICT (clawback_id) DO UPDATE SET
            idempotency_key = COALESCE(aegis_clawback_receipts.idempotency_key, EXCLUDED.idempotency_key),
            victim_account_id = COALESCE(aegis_clawback_receipts.victim_account_id, EXCLUDED.victim_account_id),
            victim_owner_name = COALESCE(aegis_clawback_receipts.victim_owner_name, EXCLUDED.victim_owner_name),
            source_mule_account_id = COALESCE(aegis_clawback_receipts.source_mule_account_id, EXCLUDED.source_mule_account_id),
            original_tx_ids = CASE
              WHEN jsonb_array_length(aegis_clawback_receipts.original_tx_ids) = 0 THEN EXCLUDED.original_tx_ids
              ELSE aegis_clawback_receipts.original_tx_ids
            END
          WHERE aegis_clawback_receipts.session_id = EXCLUDED.session_id
            AND aegis_clawback_receipts.alert_id = EXCLUDED.alert_id
            AND aegis_clawback_receipts.requested_amount_vnd = EXCLUDED.requested_amount_vnd
            AND aegis_clawback_receipts.recovered_amount_vnd = EXCLUDED.recovered_amount_vnd
            AND aegis_clawback_receipts.missing_amount_vnd = EXCLUDED.missing_amount_vnd
            AND aegis_clawback_receipts.recovery_status = EXCLUDED.recovery_status
            AND aegis_clawback_receipts.reversal_tx_id IS NOT DISTINCT FROM EXCLUDED.reversal_tx_id
            AND (
              aegis_clawback_receipts.idempotency_key IS NULL
              OR aegis_clawback_receipts.idempotency_key = EXCLUDED.idempotency_key
            )
            AND (
              aegis_clawback_receipts.victim_account_id IS NULL
              OR aegis_clawback_receipts.victim_account_id = EXCLUDED.victim_account_id
            )
            AND (
              aegis_clawback_receipts.source_mule_account_id IS NULL
              OR aegis_clawback_receipts.source_mule_account_id = EXCLUDED.source_mule_account_id
            )
          RETURNING clawback_id`,
          [
            claw.clawbackId,
            params.sessionId,
            claw.alertId,
            normalizedIdemKey,
            Math.round(claw.requestedAmountVnd ?? claw.recoveredAmountVnd),
            Math.round(claw.recoveredAmountVnd),
            Math.round(claw.missingAmountVnd ?? 0),
            claw.recoveryStatus ?? 'RECOVERED',
            claw.reversalTxId ?? null,
            claw.victimAccountId ?? null,
            claw.victimOwnerName ?? null,
            claw.sourceMuleAccountId ?? null,
            JSON.stringify(normalizedTxIds),
            claw.executedAt,
          ]
        );
        if ((clawRes.rowCount ?? clawRes.rows.length) === 0) {
          throw new ConcurrentStateConflictError(
            `Xung đột toàn vẹn biên nhận Clawback "${claw.clawbackId}": dữ liệu xung đột với bản ghi đã lưu trên Postgres.`
          );
        }
      }

      // Persist append-only operational audit logs atomically within the same ACID transaction.
      // Scoped audit_id (`<sessionId>:<audit.id>`) guarantees idempotency on retries without
      // cross-session primary-key collisions; any insert failure rolls back the entire mutation.
      for (const audit of params.nextDelta.auditLogs ?? []) {
        const scopedAuditId = audit.id.startsWith(`${params.sessionId}:`)
          ? audit.id
          : `${params.sessionId}:${audit.id}`;
        await client.query(
          `INSERT INTO aegis_audit_logs (
            audit_id, session_id, alert_id, actor, action, details_vi, created_at
          ) VALUES ($1,$2,$3,$4,$5,$6,$7)
          ON CONFLICT (audit_id) DO NOTHING`,
          [
            scopedAuditId,
            params.sessionId,
            audit.alertId,
            audit.actor,
            audit.action,
            audit.detailsVi,
            audit.timestamp,
          ]
        );
      }

      await client.query('COMMIT');
      return params.nextDelta;
    } catch (err) {
      try {
        await client.query('ROLLBACK');
      } catch {
        // Ignore secondary rollback failure
      }
      if (
        err &&
        typeof err === 'object' &&
        (err as { code?: string }).code === '23505'
      ) {
        throw new ConcurrentStateConflictError(
          'Phát hiện trùng khóa giao dịch/idempotency hoặc hoàn tiền Clawback đồng thời trên Postgres (SQLSTATE 23505).'
        );
      }
      throw err;
    } finally {
      if (typeof (client as PoolClient).release === 'function') {
        (client as PoolClient).release();
      }
    }
  }

  async revokeSession(sessionId: string): Promise<void> {
    await this.pool.query(
      `UPDATE aegis_workspace_sessions
       SET status = 'REVOKED', revoked_at = NOW(), updated_at = NOW()
       WHERE session_id = $1`,
      [sessionId]
    );
  }

  async isSessionRevoked(sessionId: string): Promise<boolean> {
    const res = await this.pool.query(
      `SELECT status, expires_at FROM aegis_workspace_sessions WHERE session_id = $1`,
      [sessionId]
    );
    const row = res.rows[0] as { status: string; expires_at: string | Date } | undefined;
    if (!row) return false;
    if (row.status === 'REVOKED' || row.status === 'EXPIRED') return true;
    const expMs = Date.parse(String(row.expires_at));
    return Number.isFinite(expMs) && expMs <= Date.now();
  }

  async ping(): Promise<PersistenceHealthPing> {
    const start = performance.now();
    try {
      await this.pool.query('SELECT 1 AS ok');
      return { mode: 'POSTGRES', ok: true, latencyMs: Math.round(performance.now() - start) };
    } catch {
      return {
        mode: 'POSTGRES',
        ok: false,
        latencyMs: Math.round(performance.now() - start),
        errorCode: 'POSTGRES_PING_FAILED',
      };
    }
  }

  async close(): Promise<void> {
    if (typeof this.pool.end === 'function') {
      await this.pool.end();
    }
  }
}

let cachedDefaultMemoryAdapter: InMemoryPersistenceAdapter | null = null;
let cachedPostgresAdapter: { url: string; adapter: PostgresPersistenceAdapter } | null = null;
let overrideAdapterForTest: WorkspacePersistenceAdapter | null = null;

export const setPersistenceAdapterForTest = (adapter: WorkspacePersistenceAdapter | null): void => {
  overrideAdapterForTest = adapter;
};

export const closeWorkspacePersistenceAdapter = async (): Promise<void> => {
  if (cachedPostgresAdapter) {
    await cachedPostgresAdapter.adapter.close();
    cachedPostgresAdapter = null;
  }
};

export const getWorkspacePersistenceAdapter = (): WorkspacePersistenceAdapter => {
  if (overrideAdapterForTest) {
    return overrideAdapterForTest;
  }

  const dbUrl = process.env.DATABASE_URL?.trim();
  const requireShared =
    process.env.AEGIS_REQUIRE_SHARED_PERSISTENCE === 'true' ||
    process.env.AEGIS_PRODUCTION_STRICT_READINESS === 'true';

  if (isValidPostgresConnectionUrl(dbUrl)) {
    try {
      if (!cachedPostgresAdapter || cachedPostgresAdapter.url !== dbUrl) {
        cachedPostgresAdapter = { url: dbUrl!, adapter: new PostgresPersistenceAdapter(dbUrl!) };
      }
      return cachedPostgresAdapter.adapter;
    } catch (err) {
      if (err instanceof PostgresTlsConfigurationError) {
        return new FailClosedPersistenceAdapter(err.reasonCode);
      }
      if (requireShared) {
        return new FailClosedPersistenceAdapter('POSTGRES_INIT_FAILED');
      }
      throw err;
    }
  }

  if (requireShared) {
    return new FailClosedPersistenceAdapter();
  }

  if (!cachedDefaultMemoryAdapter) {
    cachedDefaultMemoryAdapter = new InMemoryPersistenceAdapter();
  }
  return cachedDefaultMemoryAdapter;
};
