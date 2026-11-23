-- Wave 4.2.1A Additive Migration 002: Multi-Victim & Partial Clawback Persistence + Monotonic REVERSED Ledger Status
-- Targets: NEON-01 (aegis_clawback_receipts) & NEON-02 (aegis_ledger_transactions).
-- Properties: Additive, idempotent, preserves all existing rows, must be executed via DIRECT_URL after migration 001.

BEGIN;

-- 1. Precondition guard: fail explicitly if Wave 4.1 base schema (001_wave4_shared_persistence) is absent.
DO $$
BEGIN
  IF to_regclass(format('%I.aegis_schema_migrations', current_schema())) IS NULL
     OR to_regclass(format('%I.aegis_clawback_receipts', current_schema())) IS NULL
     OR to_regclass(format('%I.aegis_ledger_transactions', current_schema())) IS NULL THEN
    RAISE EXCEPTION
      'Migration 002 precondition failed: required base tables from 001_wave4_shared_persistence are missing in schema "%".',
      current_schema();
  END IF;
END $$;

-- 2. NEON-01: Remove legacy inline UNIQUE (session_id, alert_id) constraint on aegis_clawback_receipts
--    (default PostgreSQL name: aegis_clawback_receipts_session_id_alert_id_key) so distinct multi-victim
--    and partial clawback receipts sharing (session_id, alert_id) can persist independently.
DO $$
DECLARE
  v_constraint_name TEXT;
BEGIN
  FOR v_constraint_name IN
    SELECT c.conname
    FROM pg_constraint c
    JOIN pg_class t ON t.oid = c.conrelid
    JOIN pg_namespace n ON n.oid = t.relnamespace
    WHERE n.nspname = current_schema()
      AND t.relname = 'aegis_clawback_receipts'
      AND c.contype = 'u'
      AND (
        SELECT array_agg(a.attname::text ORDER BY a.attname)
        FROM unnest(c.conkey) AS k(attnum)
        JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = k.attnum
      ) = ARRAY['alert_id', 'session_id']
  LOOP
    EXECUTE format(
      'ALTER TABLE %I.%I DROP CONSTRAINT %I',
      current_schema(),
      'aegis_clawback_receipts',
      v_constraint_name
    );
  END LOOP;
END $$;

-- 3. NEON-01: Add missing audit & idempotency columns from ClawbackReceiptRecord (non-destructive).
--    Nullable text columns preserve any pre-existing rows created under migration 001;
--    original_tx_ids defaults to an empty JSON array for legacy rows and stores original settled txIds for new rows.
ALTER TABLE aegis_clawback_receipts
  ADD COLUMN IF NOT EXISTS idempotency_key TEXT,
  ADD COLUMN IF NOT EXISTS victim_account_id TEXT,
  ADD COLUMN IF NOT EXISTS victim_owner_name TEXT,
  ADD COLUMN IF NOT EXISTS source_mule_account_id TEXT,
  ADD COLUMN IF NOT EXISTS original_tx_ids JSONB NOT NULL DEFAULT '[]'::jsonb;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint c
    JOIN pg_class t ON t.oid = c.conrelid
    JOIN pg_namespace n ON n.oid = t.relnamespace
    WHERE n.nspname = current_schema()
      AND t.relname = 'aegis_clawback_receipts'
      AND c.conname = 'chk_aegis_clawback_original_tx_ids_array'
  ) THEN
    ALTER TABLE aegis_clawback_receipts
      ADD CONSTRAINT chk_aegis_clawback_original_tx_ids_array
      CHECK (jsonb_typeof(original_tx_ids) = 'array');
  END IF;
END $$;

-- 4. NEON-01: Lookup & business-idempotency indexes on aegis_clawback_receipts.
--    - Non-unique lookup index supports multiple receipts per (session_id, alert_id).
--    - Partial unique index on (session_id, idempotency_key) prevents duplicate execution of the same request key
--      while allowing multiple receipts when idempotency_key IS NULL or distinct.
--    - Partial unique index on (session_id, reversal_tx_id) guarantees 1:1 correspondence between a funded
--      clawback receipt and its ledger reversal transaction while permitting multiple FAILED (NULL reversal_tx_id) rows.
CREATE INDEX IF NOT EXISTS idx_aegis_clawback_session_alert
  ON aegis_clawback_receipts (session_id, alert_id, executed_at DESC);

CREATE UNIQUE INDEX IF NOT EXISTS uq_aegis_clawback_session_idem
  ON aegis_clawback_receipts (session_id, idempotency_key)
  WHERE idempotency_key IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_aegis_clawback_session_reversal_tx
  ON aegis_clawback_receipts (session_id, reversal_tx_id)
  WHERE reversal_tx_id IS NOT NULL;

-- 5. NEON-02: Database-level defense-in-depth trigger on aegis_ledger_transactions.
--    Enforces monotonic SETTLED/COMPLETED -> REVERSED transitions, treats REVERSED as terminal,
--    and prevents mutation of immutable transaction attributes on UPDATE.
CREATE OR REPLACE FUNCTION aegis_guard_ledger_tx_status_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.session_id IS DISTINCT FROM OLD.session_id
     OR NEW.alert_id IS DISTINCT FROM OLD.alert_id
     OR NEW.sender_account_id IS DISTINCT FROM OLD.sender_account_id
     OR NEW.receiver_account_id IS DISTINCT FROM OLD.receiver_account_id
     OR NEW.amount_vnd IS DISTINCT FROM OLD.amount_vnd
     OR NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key
     OR NEW.tx_kind IS DISTINCT FROM OLD.tx_kind
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION
      'Immutable ledger transaction attributes cannot be modified on tx_id "%".',
      OLD.tx_id;
  END IF;

  IF OLD.status = NEW.status THEN
    RETURN NEW;
  END IF;

  IF OLD.status = 'REVERSED' THEN
    RAISE EXCEPTION
      'Invalid ledger status regression on tx_id "%": terminal REVERSED cannot transition to "%".',
      OLD.tx_id,
      NEW.status;
  END IF;

  IF NEW.status = 'REVERSED' AND OLD.status IN ('SETTLED', 'COMPLETED') THEN
    RETURN NEW;
  END IF;

  RAISE EXCEPTION
    'Disallowed ledger transaction status transition on tx_id "%": "%" -> "%".',
    OLD.tx_id,
    OLD.status,
    NEW.status;
END;
$$;

DROP TRIGGER IF EXISTS trg_aegis_ledger_tx_status_guard ON aegis_ledger_transactions;
CREATE TRIGGER trg_aegis_ledger_tx_status_guard
  BEFORE UPDATE ON aegis_ledger_transactions
  FOR EACH ROW
  EXECUTE FUNCTION aegis_guard_ledger_tx_status_transition();

-- 6. Record migration version idempotently.
INSERT INTO aegis_schema_migrations (version, description)
VALUES (
  '002_clawback_multi_victim_and_tx_status',
  'Enable multi-victim & partial clawback receipts with idempotency indexes and monotonic REVERSED ledger transaction transitions'
)
ON CONFLICT (version) DO NOTHING;

COMMIT;
