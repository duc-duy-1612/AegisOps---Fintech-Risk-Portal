-- Wave 4.1 Non-Destructive Rollback Reference Script (Staging/Pre-Launch Reset Only)
-- WARNING: Do NOT execute against live production data without exporting a backup snapshot first.

DROP TABLE IF EXISTS aegis_audit_logs;
DROP TABLE IF EXISTS aegis_clawback_receipts;
DROP TABLE IF EXISTS aegis_ledger_entries;
DROP TABLE IF EXISTS aegis_ledger_transactions;
DROP TABLE IF EXISTS aegis_hitl_feedback;
DROP TABLE IF EXISTS aegis_workspace_sessions;
DELETE FROM aegis_schema_migrations WHERE version = '001_wave4_shared_persistence';
