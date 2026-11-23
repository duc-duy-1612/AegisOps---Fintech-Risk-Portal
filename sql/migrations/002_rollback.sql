-- Wave 4.2.1A Safe Rollback Script for Migration 002 (NEON-01 & NEON-02)
-- Execute ONLY via DIRECT_URL after taking a verified Neon branch snapshot.
--
-- SAFETY & IRREVERSIBILITY NOTICE:
-- 1. This script NEVER drops aegis_clawback_receipts or aegis_ledger_transactions and NEVER deletes records.
-- 2. Restoring UNIQUE (session_id, alert_id) is IRREVERSIBLE WITHOUT DATA LOSS once multiple valid
--    multi-victim or partial clawback receipts exist for any (session_id, alert_id). If duplicates exist,
--    this script aborts with an explicit error instead of deleting or consolidating financial audit rows.
-- 3. Additive audit columns (idempotency_key, victim_account_id, victim_owner_name, source_mule_account_id,
--    original_tx_ids) are intentionally preserved non-destructively so previously written audit metadata is
--    not lost. Dropping them requires an explicit post-archive maintenance decision.
-- 4. Already-persisted REVERSED values in aegis_ledger_transactions.status CANNOT be safely auto-reverted
--    to prior SETTLED/COMPLETED values by DDL rollback; recovering pre-reversal states requires a forward-fix
--    or restoring a verified Neon PITR / pre-migration branch snapshot.

BEGIN;

-- 1. Verify required tables exist before rolling back.
DO $$
BEGIN
  IF to_regclass(format('%I.aegis_clawback_receipts', current_schema())) IS NULL
     OR to_regclass(format('%I.aegis_ledger_transactions', current_schema())) IS NULL
     OR to_regclass(format('%I.aegis_schema_migrations', current_schema())) IS NULL THEN
    RAISE EXCEPTION
      'Rollback 002 aborted: required tables are missing in schema "%".',
      current_schema();
  END IF;
END $$;

-- 2. Abort safely if multiple clawback receipts share (session_id, alert_id).
--    Never delete or merge financial audit records to force rollback.
DO $$
DECLARE
  v_duplicate_pairs INTEGER;
BEGIN
  SELECT COUNT(*)
  INTO v_duplicate_pairs
  FROM (
    SELECT session_id, alert_id
    FROM aegis_clawback_receipts
    GROUP BY session_id, alert_id
    HAVING COUNT(*) > 1
  ) dup;

  IF v_duplicate_pairs > 0 THEN
    RAISE EXCEPTION
      'Rollback 002 aborted: % (session_id, alert_id) group(s) contain multiple clawback receipts. Restoring UNIQUE (session_id, alert_id) would require deleting financial audit records. Use a forward-fix or restore from a verified Neon backup/PITR snapshot.',
      v_duplicate_pairs;
  END IF;
END $$;

-- 3. Remove migration 002 ledger transition trigger & function (preserves all aegis_ledger_transactions rows).
DROP TRIGGER IF EXISTS trg_aegis_ledger_tx_status_guard ON aegis_ledger_transactions;
DROP FUNCTION IF EXISTS aegis_guard_ledger_tx_status_transition();

-- 4. Remove migration 002 clawback indexes (preserves all rows and additive audit columns).
DROP INDEX IF EXISTS uq_aegis_clawback_session_reversal_tx;
DROP INDEX IF EXISTS uq_aegis_clawback_session_idem;
DROP INDEX IF EXISTS idx_aegis_clawback_session_alert;

-- 5. Restore legacy UNIQUE (session_id, alert_id) constraint only because step 2 proved zero duplicates exist.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
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
  ) THEN
    ALTER TABLE aegis_clawback_receipts
      ADD CONSTRAINT aegis_clawback_receipts_session_id_alert_id_key
      UNIQUE (session_id, alert_id);
  END IF;
END $$;

-- 6. Remove migration 002 registration entry.
DELETE FROM aegis_schema_migrations
WHERE version = '002_clawback_multi_victim_and_tx_status';

COMMIT;
