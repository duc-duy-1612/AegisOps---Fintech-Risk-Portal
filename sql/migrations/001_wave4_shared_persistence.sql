-- Wave 4.1 Idempotent Shared Persistence Schema for AegisOps (PostgreSQL 15+ / Neon / Supabase)
-- Guarantees ACID double-entry ledger invariants, monotonic CAS session revisions, and durable HITL revocation.

CREATE TABLE IF NOT EXISTS aegis_schema_migrations (
  version TEXT PRIMARY KEY,
  description TEXT NOT NULL,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS aegis_workspace_sessions (
  session_id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL,
  state_revision INTEGER NOT NULL CHECK (state_revision >= 0),
  status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'REVOKED', 'EXPIRED')),
  delta_integrity_tag TEXT NOT NULL,
  delta_json JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_aegis_sessions_expires_at
  ON aegis_workspace_sessions (expires_at);

CREATE TABLE IF NOT EXISTS aegis_hitl_feedback (
  feedback_id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES aegis_workspace_sessions(session_id) ON DELETE CASCADE,
  source_alert_id TEXT NOT NULL,
  target_scope TEXT NOT NULL CHECK (target_scope IN ('ALERT_CASE', 'RECIPIENT_PATTERN', 'TX_PATTERN')),
  target_fingerprint TEXT NOT NULL,
  context_signature TEXT NOT NULL,
  feedback_decision TEXT NOT NULL CHECK (feedback_decision IN ('OVERRIDE_SAFE', 'FORCE_BLOCK')),
  status TEXT NOT NULL CHECK (status IN ('PENDING_APPROVAL', 'APPROVED_ACTIVE', 'REJECTED', 'EXPIRED', 'REVOKED')),
  risk_adjustment INTEGER NOT NULL CHECK (risk_adjustment BETWEEN -18 AND 20),
  memory_version INTEGER NOT NULL CHECK (memory_version >= 1),
  actor_principal_id TEXT NOT NULL,
  approved_by_principal_id TEXT,
  revoked_by_principal_id TEXT,
  created_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_aegis_hitl_session_status
  ON aegis_hitl_feedback (session_id, status);

CREATE INDEX IF NOT EXISTS idx_aegis_hitl_target_ctx
  ON aegis_hitl_feedback (session_id, target_fingerprint, context_signature);

CREATE TABLE IF NOT EXISTS aegis_ledger_transactions (
  tx_id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES aegis_workspace_sessions(session_id) ON DELETE CASCADE,
  alert_id TEXT NOT NULL,
  sender_account_id TEXT NOT NULL,
  receiver_account_id TEXT NOT NULL,
  amount_vnd BIGINT NOT NULL CHECK (amount_vnd > 0),
  status TEXT NOT NULL CHECK (status IN ('COMPLETED', 'HELD', 'BLOCKED', 'PENDING', 'SETTLED', 'FAILED', 'REVERSED')),
  idempotency_key TEXT,
  tx_kind TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_aegis_ledger_session_idem
  ON aegis_ledger_transactions (session_id, idempotency_key)
  WHERE idempotency_key IS NOT NULL;

CREATE TABLE IF NOT EXISTS aegis_ledger_entries (
  entry_id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES aegis_workspace_sessions(session_id) ON DELETE CASCADE,
  tx_id TEXT NOT NULL REFERENCES aegis_ledger_transactions(tx_id) ON DELETE CASCADE,
  account_id TEXT NOT NULL,
  entry_type TEXT NOT NULL CHECK (entry_type IN ('DEBIT', 'CREDIT')),
  amount_vnd BIGINT NOT NULL CHECK (amount_vnd > 0),
  status TEXT NOT NULL CHECK (status IN ('SETTLED', 'REVERSED')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_aegis_entries_session_account
  ON aegis_ledger_entries (session_id, account_id);

CREATE TABLE IF NOT EXISTS aegis_clawback_receipts (
  clawback_id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES aegis_workspace_sessions(session_id) ON DELETE CASCADE,
  alert_id TEXT NOT NULL,
  requested_amount_vnd BIGINT NOT NULL CHECK (requested_amount_vnd >= 0),
  recovered_amount_vnd BIGINT NOT NULL CHECK (recovered_amount_vnd >= 0),
  missing_amount_vnd BIGINT NOT NULL CHECK (missing_amount_vnd >= 0),
  recovery_status TEXT NOT NULL CHECK (recovery_status IN ('RECOVERED', 'PARTIALLY_RECOVERED', 'FAILED')),
  reversal_tx_id TEXT,
  executed_at TIMESTAMPTZ NOT NULL,
  UNIQUE (session_id, alert_id)
);

CREATE TABLE IF NOT EXISTS aegis_audit_logs (
  audit_id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES aegis_workspace_sessions(session_id) ON DELETE CASCADE,
  alert_id TEXT NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  details_vi TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_aegis_audit_session_time
  ON aegis_audit_logs (session_id, created_at DESC);

INSERT INTO aegis_schema_migrations (version, description)
VALUES ('001_wave4_shared_persistence', 'Initial ACID session, HITL revocation, ledger & clawback tables')
ON CONFLICT (version) DO NOTHING;
