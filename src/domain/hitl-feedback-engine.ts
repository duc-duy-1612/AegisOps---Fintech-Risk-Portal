/**
 * Pure Domain Adaptive HITL Feedback Memory Engine (Wave 3):
 * - Structured feedback provenance, Maker-Checker governance, scope/context binding, TTL expiry & revocation.
 * - Strictly bounded risk adjustments: NEVER whitelists permanently, NEVER overrides hard security blocks,
 *   detects SAFE vs FORCE_BLOCK conflicts and marks NEEDS_REVIEW cleanly instead of naive last-write-wins.
 */
import type {
  Account,
  AdaptiveFeedbackSummary,
  FraudAlert,
  HitlFeedbackDecision,
  HitlFeedbackLifecycleStatus,
  HitlFeedbackMemoryRecord,
  HitlFeedbackTargetScope,
  RiskAttributionFactor,
} from './types';

export const HITL_MAX_SAFE_REDUCTION = -18;
export const HITL_MIN_SAFE_REDUCTION = -5;
export const HITL_MIN_BLOCK_BOOST = 10;
export const HITL_MAX_BLOCK_BOOST = 20;

export const clampHitlRiskAdjustment = (
  decision: HitlFeedbackDecision,
  requestedDelta?: number
): number => {
  if (decision === 'OVERRIDE_SAFE') {
    const val = typeof requestedDelta === 'number' && Number.isFinite(requestedDelta) ? Math.round(requestedDelta) : -12;
    return Math.max(HITL_MAX_SAFE_REDUCTION, Math.min(HITL_MIN_SAFE_REDUCTION, val));
  }
  const val = typeof requestedDelta === 'number' && Number.isFinite(requestedDelta) ? Math.round(requestedDelta) : 15;
  return Math.max(HITL_MIN_BLOCK_BOOST, Math.min(HITL_MAX_BLOCK_BOOST, val));
};

export const buildHitlContextSignature = (params: {
  scenarioCode: string;
  recipientAccountType?: Account['accountType'];
  channel?: string;
}): string => {
  const scen = params.scenarioCode || 'UNKNOWN';
  const recType = params.recipientAccountType || 'CONSUMER';
  const chan = params.channel || 'P2P_WALLET';
  return `${scen}:${recType}:${chan}`.toUpperCase();
};

export const resolveEffectiveFeedbackStatus = (
  record: HitlFeedbackMemoryRecord,
  nowMs: number = Date.now()
): HitlFeedbackLifecycleStatus => {
  if (record.status === 'REVOKED' || record.status === 'REJECTED' || record.status === 'PENDING_APPROVAL') {
    return record.status;
  }
  const expMs = Date.parse(record.expiresAt);
  if (Number.isFinite(expMs) && expMs <= nowMs) {
    return 'EXPIRED';
  }
  return record.status;
};

export const doesFeedbackMatchAlertContext = (params: {
  record: HitlFeedbackMemoryRecord;
  alert: FraudAlert;
  targetAccount?: Account;
  targetFingerprint: string;
  legacyTargetFingerprints?: readonly string[];
  currentContextSignature: string;
  nowMs?: number;
}): boolean => {
  const effectiveStatus = resolveEffectiveFeedbackStatus(params.record, params.nowMs);
  if (effectiveStatus !== 'APPROVED_ACTIVE') {
    return false;
  }

  const r = params.record;
  if (r.targetScope === 'ALERT_CASE') {
    return r.sourceAlertId === params.alert.id;
  }

  const matchesLegacyFingerprint =
    Array.isArray(params.legacyTargetFingerprints) &&
    params.legacyTargetFingerprints.includes(r.targetFingerprint);

  const targetMatches =
    r.targetFingerprint === params.targetFingerprint ||
    matchesLegacyFingerprint ||
    (r.recipientAccountId !== undefined && r.recipientAccountId === params.alert.targetRecipientAccountId);

  if (!targetMatches) {
    return false;
  }

  // Scoped Context Binding: SAFE feedback only applies in matching context; never transfers across mismatched risk contexts!
  return r.contextSignature === params.currentContextSignature;
};

export interface EvaluateAdaptiveFeedbackResult {
  summary: AdaptiveFeedbackSummary;
  factors: RiskAttributionFactor[];
  finalScore: number;
}

export const evaluateAdaptiveHitlFeedback = (params: {
  baseScore: number;
  alert: FraudAlert;
  targetAccount?: Account;
  targetFingerprint: string;
  legacyTargetFingerprints?: readonly string[];
  currentContextSignature: string;
  feedbackMemory: HitlFeedbackMemoryRecord[];
  hardCriticalSignalsPresent: boolean;
  nowMs?: number;
}): EvaluateAdaptiveFeedbackResult => {
  const nowMs = params.nowMs ?? Date.now();
  const baseScore = Math.max(0, Math.min(99, Math.round(params.baseScore)));

  const matchingActive = params.feedbackMemory.filter((rec) =>
    doesFeedbackMatchAlertContext({
      record: rec,
      alert: params.alert,
      targetAccount: params.targetAccount,
      targetFingerprint: params.targetFingerprint,
      legacyTargetFingerprints: params.legacyTargetFingerprints,
      currentContextSignature: params.currentContextSignature,
      nowMs,
    })
  );

  if (matchingActive.length === 0) {
    return {
      summary: {
        appliedRecords: [],
        conflictDetected: false,
        hardRuleBlockedOverride: false,
        baseScoreBeforeFeedback: baseScore,
        finalScoreAfterFeedback: baseScore,
      },
      factors: [],
      finalScore: baseScore,
    };
  }

  const safeRecords = matchingActive.filter((r) => r.feedbackDecision === 'OVERRIDE_SAFE');
  const blockRecords = matchingActive.filter((r) => r.feedbackDecision === 'FORCE_BLOCK');

  // Conflict Detection: Both active SAFE and active FORCE_BLOCK on same scoped target -> NEEDS_REVIEW (no naive last-write-wins!)
  if (safeRecords.length > 0 && blockRecords.length > 0) {
    return {
      summary: {
        appliedRecords: [],
        conflictDetected: true,
        needsReviewVi: `XUNG ĐỘT PHẢN HỒI HITL (${safeRecords.length} SAFE vs ${blockRecords.length} FORCE_BLOCK): Không tự động hạ điểm — Yêu cầu L2 rà soát & thu hồi phản hồi xung đột (NEEDS_REVIEW).`,
        hardRuleBlockedOverride: false,
        baseScoreBeforeFeedback: baseScore,
        finalScoreAfterFeedback: baseScore,
      },
      factors: [],
      finalScore: baseScore,
    };
  }

  const factors: RiskAttributionFactor[] = [];
  const appliedRecords: AdaptiveFeedbackSummary['appliedRecords'] = [];
  let hardRuleBlockedOverride = false;
  let hardRuleNoticeVi: string | undefined;
  let deltaSum = 0;

  if (safeRecords.length > 0) {
    // Only apply most recent approved record in deterministic bounded scope (avoid stacking multiple overrides to 0!)
    const selectedSafe = safeRecords[0]!;
    if (params.hardCriticalSignalsPresent) {
      hardRuleBlockedOverride = true;
      hardRuleNoticeVi =
        `Phản hồi ${selectedSafe.feedbackId} (SAFE) KHÔNG ĐƯỢC ÁP DỤNG vì tồn tại tín hiệu bảo mật cứng (ATO/Deepfake/Mule Shield/In-Call Phishing).`;
    } else {
      const boundedDelta = clampHitlRiskAdjustment('OVERRIDE_SAFE', selectedSafe.riskAdjustment);
      deltaSum += boundedDelta;
      const expl = `Bộ nhớ HITL đã duyệt (${selectedSafe.feedbackId} • Phạm vi ${selectedSafe.targetScope}): Giảm trừ ${boundedDelta}đ (${selectedSafe.reasonCode}).`;
      appliedRecords.push({
        feedbackId: selectedSafe.feedbackId,
        feedbackDecision: 'OVERRIDE_SAFE',
        targetScope: selectedSafe.targetScope,
        riskAdjustment: boundedDelta,
        reasonCode: selectedSafe.reasonCode,
        explanationVi: expl,
      });
      factors.push({
        id: `HITL-SAFE-${selectedSafe.feedbackId}`,
        labelVi: `Adaptive HITL SAFE (${selectedSafe.targetScope})`,
        deltaScore: boundedDelta,
        kind: 'ADAPTIVE_HITL_DAMPENER',
        metricDetail: `${selectedSafe.feedbackId} • Hết hạn ${new Date(selectedSafe.expiresAt).toLocaleString('vi-VN')}`,
      });
    }
  } else if (blockRecords.length > 0) {
    const selectedBlock = blockRecords[0]!;
    const boundedDelta = clampHitlRiskAdjustment('FORCE_BLOCK', selectedBlock.riskAdjustment);
    deltaSum += boundedDelta;
    const expl = `Bộ nhớ HITL đã duyệt (${selectedBlock.feedbackId} • Phạm vi ${selectedBlock.targetScope}): Cộng +${boundedDelta}đ cảnh giác (${selectedBlock.reasonCode}).`;
    appliedRecords.push({
      feedbackId: selectedBlock.feedbackId,
      feedbackDecision: 'FORCE_BLOCK',
      targetScope: selectedBlock.targetScope,
      riskAdjustment: boundedDelta,
      reasonCode: selectedBlock.reasonCode,
      explanationVi: expl,
    });
    factors.push({
      id: `HITL-BLK-${selectedBlock.feedbackId}`,
      labelVi: `Adaptive HITL FORCE_BLOCK (${selectedBlock.targetScope})`,
      deltaScore: boundedDelta,
      kind: 'ADAPTIVE_HITL_BOOSTER',
      metricDetail: `${selectedBlock.feedbackId} • ${selectedBlock.analystRationale}`,
    });
  }

  const adjusted = Math.max(5, Math.min(99, baseScore + deltaSum));
  return {
    summary: {
      appliedRecords,
      conflictDetected: false,
      hardRuleBlockedOverride,
      hardRuleNoticeVi,
      baseScoreBeforeFeedback: baseScore,
      finalScoreAfterFeedback: adjusted,
    },
    factors,
    finalScore: adjusted,
  };
};

export const hasDuplicateActiveFeedback = (params: {
  existing: HitlFeedbackMemoryRecord[];
  targetFingerprint: string;
  legacyTargetFingerprints?: readonly string[];
  contextSignature: string;
  feedbackDecision: HitlFeedbackDecision;
  targetScope: HitlFeedbackTargetScope;
  sourceAlertId: string;
  nowMs?: number;
}): boolean => {
  const nowMs = params.nowMs ?? Date.now();
  return params.existing.some((rec) => {
    const st = resolveEffectiveFeedbackStatus(rec, nowMs);
    if (st !== 'APPROVED_ACTIVE' && st !== 'PENDING_APPROVAL') return false;
    const fpMatches =
      rec.targetFingerprint === params.targetFingerprint ||
      (Array.isArray(params.legacyTargetFingerprints) &&
        params.legacyTargetFingerprints.includes(rec.targetFingerprint));
    return (
      fpMatches &&
      rec.contextSignature === params.contextSignature &&
      rec.feedbackDecision === params.feedbackDecision &&
      rec.targetScope === params.targetScope &&
      (params.targetScope !== 'ALERT_CASE' || rec.sourceAlertId === params.sourceAlertId)
    );
  });
};
