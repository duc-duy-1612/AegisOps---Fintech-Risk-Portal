import type {
  CrossCaseLink,
  ForensicSuiteOutput,
  FraudAlert,
} from './types';

export interface BatchTriageSummary {
  totalAlerts: number;
  linkedCampaignClusters: Array<{
    sharedEntityId: string;
    alertIds: string[];
    descriptionVi: string;
  }>;
  autoClearCandidateIds: string[];
  correlationsByAlertId: Record<string, CrossCaseLink>;
}

/**
 * Pure Domain Cross-Case Campaign Correlator (Sardine / Feedzai Pattern)
 * Detects hidden links between separate alerts sharing the same Mule account or Emulator Device.
 */
export const computeCrossCaseCorrelations = (
  alerts: readonly FraudAlert[],
  forensicsByAlertId: Record<string, ForensicSuiteOutput>
): BatchTriageSummary => {
  const infraToAlerts = new Map<string, Set<string>>();

  for (const alert of alerts) {
    const suite = forensicsByAlertId[alert.id];
    const entities = new Set<string>();
    if (alert.targetRecipientAccountId) {
      entities.add(alert.targetRecipientAccountId);
    }
    if (suite) {
      suite.graphNodes.forEach((node) => {
        if (node.nodeKind === 'SHARED_DEVICE' || node.nodeKind === 'SUSPECT_MULE') {
          entities.add(node.id);
        }
      });
    }
    for (const entId of entities) {
      const set = infraToAlerts.get(entId) ?? new Set<string>();
      set.add(alert.id);
      infraToAlerts.set(entId, set);
    }
  }

  const linkedCampaignClusters: BatchTriageSummary['linkedCampaignClusters'] = [];
  const seenClusterKeys = new Set<string>();

  for (const [entId, alertSet] of infraToAlerts.entries()) {
    if (alertSet.size >= 2) {
      const sortedIds = Array.from(alertSet).sort();
      const clusterKey = sortedIds.join('|');
      if (!seenClusterKeys.has(clusterKey)) {
        seenClusterKeys.add(clusterKey);
        linkedCampaignClusters.push({
          sharedEntityId: entId,
          alertIds: sortedIds,
          descriptionVi: `Phát hiện ${sortedIds.length} vụ việc (${sortedIds.join(' ↔ ')}) cùng liên kết hạ tầng ${entId}`,
        });
      }
    }
  }

  const autoClearCandidateIds = alerts
    .filter((a) => a.scenarioCode === 'SMART_FALSE_POSITIVE' && a.deterministicRiskScore < 25)
    .map((a) => a.id);

  const correlationsByAlertId: Record<string, CrossCaseLink> = {};
  for (const alert of alerts) {
    const linked = new Set<string>();
    const sharedInfra = new Set<string>();

    for (const [entId, alertSet] of infraToAlerts.entries()) {
      if (alertSet.has(alert.id) && alertSet.size >= 2) {
        sharedInfra.add(entId);
        alertSet.forEach((otherId) => {
          if (otherId !== alert.id) linked.add(otherId);
        });
      }
    }

    const isAutoClear = autoClearCandidateIds.includes(alert.id);
    const linkedArr = Array.from(linked);
    const infraArr = Array.from(sharedInfra);

    correlationsByAlertId[alert.id] = {
      alertId: alert.id,
      linkedAlertIds: linkedArr,
      sharedInfrastructureIds: infraArr,
      triageActionHint: isAutoClear
        ? 'AUTO_CLEAR_SAFE_FP'
        : linkedArr.length > 0
          ? 'CLUSTER_HIGH_PRIORITY'
          : 'ISOLATED_CRITICAL',
      summaryVi: isAutoClear
        ? 'Khuyến nghị Auto-Clear (Báo động giả an toàn)'
        : linkedArr.length > 0
          ? `Liên kết băng nhóm với ${linkedArr.join(', ')} qua ${infraArr[0]}`
          : 'Sự cố đơn lẻ cần xử lý độc lập',
    };
  }

  return {
    totalAlerts: alerts.length,
    linkedCampaignClusters,
    autoClearCandidateIds,
    correlationsByAlertId,
  };
};
