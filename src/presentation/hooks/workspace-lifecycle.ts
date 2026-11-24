import type { SessionDeltaSnapshot } from '@/domain/types';

export const SESSION_ID_STORAGE_KEY = 'aegisops_session_id_v1';
export const DELTA_STORAGE_KEY = 'aegisops_session_delta_v1';

const CONFIRMED_SESSION_INVALIDATION_CODES = new Set([
  'SESSION_REVOKED',
  'SESSION_OWNERSHIP_REQUIRED',
  'PREDICTABLE_DEFAULT_SESSION_FORBIDDEN',
  'CROSS_SESSION_SWITCH_FORBIDDEN',
  'UNAUTHORIZED',
]);

/**
 * Determines whether a `/api/session` failure indicates an expired, revoked, or non-owned
 * session that must be rotated (clearing stale localStorage delta), as opposed to a transient
 * server/network/rate-limit error (where localStorage MUST be preserved).
 */
export const isConfirmedSessionInvalidationResponse = (
  status: number,
  errorCode?: string | null
): boolean => {
  if (status !== 401 && status !== 403) {
    return false;
  }
  const normalized = (errorCode ?? '').trim().toUpperCase();
  if (!normalized) {
    // Legacy/bare 401 without error code indicates invalid/expired session cookie;
    // bare 403 without a confirmed session code (e.g. DEMO_PERSONA_SWITCH_DISABLED or CSRF) must NOT wipe localStorage.
    return status === 401;
  }
  return CONFIRMED_SESSION_INVALIDATION_CODES.has(normalized);
};

/**
 * Prevents cross-session localStorage pollution (`403 CROSS_SESSION_ACCESS_DENIED`):
 * discards any stored delta whose `sessionId` belongs to a different session than `activeSessionId`.
 */
export const filterMatchingSessionDelta = (
  delta: Partial<SessionDeltaSnapshot> | null | undefined,
  activeSessionId: string
): Partial<SessionDeltaSnapshot> | null => {
  if (!delta) return null;
  if (delta.sessionId && delta.sessionId !== activeSessionId) {
    return null;
  }
  return delta;
};

export interface WorkspaceOperationToken {
  epoch: number;
  sessionId: string;
  controller: AbortController;
  finish: () => void;
}

export interface WorkspaceAsyncCoordinator {
  getEpoch: () => number;
  getActiveSessionId: () => string;
  setActiveSessionId: (sid: string) => void;
  activate: () => void;
  isActive: () => boolean;
  beginOperation: (sid: string) => WorkspaceOperationToken;
  isCurrent: (token: Pick<WorkspaceOperationToken, 'epoch' | 'sessionId'>) => boolean;
  invalidateAll: (nextSessionId?: string) => number;
  dispose: () => void;
  getInFlightCount: () => number;
}

/**
 * Epoch + AbortController coordinator preventing stale async responses from overwriting
 * newer React state or localStorage after Reset Demo, session rotation, or component unmount.
 *
 * React Strict Mode lifecycle safety:
 * - `dispose()` marks the coordinator inactive, increments `epoch` monotonically, and aborts
 *   all in-flight controllers so pre-cleanup work can NEVER commit.
 * - `activate()` re-enables the same coordinator instance on Strict Mode effect replay without
 *   decrementing `epoch` or resurrecting previously invalidated operation tokens.
 */
export const createWorkspaceAsyncCoordinator = (
  initialSessionId: string
): WorkspaceAsyncCoordinator => {
  let epoch = 0;
  let activeSessionId = initialSessionId;
  let disposed = false;
  const inFlight = new Set<AbortController>();

  const abortAll = () => {
    for (const ctrl of Array.from(inFlight)) {
      try {
        ctrl.abort();
      } catch {
        // Ignore abort errors
      }
      inFlight.delete(ctrl);
    }
  };

  return {
    getEpoch: () => epoch,
    getActiveSessionId: () => activeSessionId,
    setActiveSessionId: (sid: string) => {
      activeSessionId = sid;
    },
    activate: () => {
      // Re-enables the coordinator on Strict Mode remount while preserving monotonic `epoch`,
      // so operations started before `dispose()` remain permanently invalid.
      disposed = false;
    },
    isActive: () => !disposed,
    beginOperation: (sid: string): WorkspaceOperationToken => {
      const controller = new AbortController();
      inFlight.add(controller);
      const capturedEpoch = epoch;
      return {
        epoch: capturedEpoch,
        sessionId: sid,
        controller,
        finish: () => {
          inFlight.delete(controller);
        },
      };
    },
    isCurrent: (token) =>
      !disposed && token.epoch === epoch && token.sessionId === activeSessionId,
    invalidateAll: (nextSessionId?: string) => {
      epoch += 1;
      if (nextSessionId !== undefined) {
        activeSessionId = nextSessionId;
      }
      abortAll();
      return epoch;
    },
    dispose: () => {
      disposed = true;
      epoch += 1;
      abortAll();
    },
    getInFlightCount: () => inFlight.size,
  };
};
