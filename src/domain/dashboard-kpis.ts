/**
 * Pure Domain Dashboard KPI Calculator (CR-1 Workstream E1):
 * Eliminates all fabricated fixed offsets (+1 false positive, static 6.4s MTTI,
 * and 25,000,000 VND * mitigatedCount fallback). Every KPI has explicit provenance.
 */
import type {
  ClawbackReceiptRecord,
  FraudAlert,
  InvestigationReport,
  Transaction,
} from './types';

export interface DashboardKpiMetrics {
  confirmedBlockedTransactionVnd: number;
  transactionsHeldForReviewVnd: number;
  recoveredClawbackVnd: number;
  selfRescuedAmountVnd: number;
  totalConfirmedBlockedAndRecoveredVnd: number;
  alertsMarkedBenignCount: number;
  mitigatedAlertsCount: number;
  openAlertsCount: number;
  measuredReportCount: number;
  averageInvestigationLatencyMs: number | null;
}

export const computeDashboardKpiMetrics = (params: {
  alerts: readonly FraudAlert[];
  transactions: readonly Transaction[];
  clawbackReceipts: readonly ClawbackReceiptRecord[];
  reportsByAlertId: Readonly<Record<string, InvestigationReport>>;
  selfRescuedAmountVnd?: number;
}): DashboardKpiMetrics => {
  const confirmedBlockedTransactionVnd = params.transactions
    .filter((t) => t.status === 'BLOCKED')
    .reduce((sum, t) => sum + Math.max(0, Math.round(t.amountVnd || 0)), 0);

  const transactionsHeldForReviewVnd = params.transactions
    .filter((t) => t.status === 'HELD')
    .reduce((sum, t) => sum + Math.max(0, Math.round(t.amountVnd || 0)), 0);

  const recoveredClawbackVnd = params.clawbackReceipts.reduce(
    (sum, c) => sum + Math.max(0, Math.round(c.recoveredAmountVnd || 0)),
    0
  );

  const selfRescuedAmountVnd = Math.max(0, Math.round(params.selfRescuedAmountVnd ?? 0));
  const totalConfirmedBlockedAndRecoveredVnd =
    confirmedBlockedTransactionVnd + recoveredClawbackVnd + selfRescuedAmountVnd;

  const alertsMarkedBenignCount = params.alerts.filter(
    (a) => a.status === 'DISMISSED_SAFE'
  ).length;
  const mitigatedAlertsCount = params.alerts.filter((a) => a.status === 'MITIGATED').length;
  const openAlertsCount = params.alerts.filter(
    (a) => a.status === 'OPEN' || a.status === 'INVESTIGATING'
  ).length;

  const measuredLatencies = Object.values(params.reportsByAlertId)
    .map((r) => r?.latencyMs)
    .filter((ms): ms is number => typeof ms === 'number' && Number.isFinite(ms) && ms >= 0);

  const averageInvestigationLatencyMs =
    measuredLatencies.length > 0
      ? Math.round(
          measuredLatencies.reduce((sum, ms) => sum + ms, 0) / measuredLatencies.length
        )
      : null;

  return {
    confirmedBlockedTransactionVnd,
    transactionsHeldForReviewVnd,
    recoveredClawbackVnd,
    selfRescuedAmountVnd,
    totalConfirmedBlockedAndRecoveredVnd,
    alertsMarkedBenignCount,
    mitigatedAlertsCount,
    openAlertsCount,
    measuredReportCount: measuredLatencies.length,
    averageInvestigationLatencyMs,
  };
};
