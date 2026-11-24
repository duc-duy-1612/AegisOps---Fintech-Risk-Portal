import { z } from 'zod';

export type AccountType = 'CONSUMER' | 'MERCHANT' | 'MULE_SUSPECT' | 'TRUSTED_INSTITUTION';
export type AccountStatus = 'ACTIVE' | 'FROZEN' | 'STEP_UP_REQUIRED';
export type AlertSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
export type AlertStatus = 'OPEN' | 'INVESTIGATING' | 'MITIGATED' | 'DISMISSED_SAFE';
export type ScenarioCode =
  | 'CYBER_ATO_MULE'
  | 'BUSINESS_LOGIC_RACE'
  | 'MULTIMODAL_APP_FRAUD'
  | 'SMART_FALSE_POSITIVE'
  | 'CUSTOM_SANDBOX';

export type ContestTrack = 'AI_ASSISTANT' | 'CYBERSECURITY' | 'ANTI_SCAM';

export type CaseClassification =
  | 'CONFIRMED_ATO_MULE'
  | 'CONFIRMED_LOGIC_ABUSE'
  | 'CONFIRMED_APP_SCAM'
  | 'FALSE_POSITIVE_SAFE';

export interface Account {
  id: string;
  ownerName: string;
  accountNumber: string;
  bankOrWalletName: string;
  accountType: AccountType;
  status: AccountStatus;
  balanceVnd: number;
  avgTxAmountVnd: number;
  kycLevel: 'LEVEL_1' | 'LEVEL_2_BIOMETRIC';
  primaryDeviceId: string;
  accountAgeDays: number;
}

export interface DeviceFingerprint {
  id: string;
  osBrowser: string;
  ipAddress: string;
  asnLocation: string;
  isEmulatorOrRooted: boolean;
  linkedAccountIds: string[];
}

export interface AuthSessionLog {
  id: string;
  accountId: string;
  deviceId: string;
  eventType:
    | 'LOGIN_SUCCESS'
    | 'PASSWORD_CHANGE'
    | 'REFRESH_TOKEN_REPLAY'
    | 'SESSION_SURVIVED_RESET'
    | 'BIOMETRIC_STEP_UP_PASS'
    | 'DEEPFAKE_VIRTUAL_CAM_INJECTION';
  sessionFamilyId: string;
  survivedCredentialReset: boolean;
  ipAddress: string;
  location: string;
  timestamp: string;
  summary: string;
}

export type TransactionStatus =
  | 'COMPLETED'
  | 'HELD'
  | 'BLOCKED'
  | 'PENDING'
  | 'SETTLED'
  | 'FAILED'
  | 'REVERSED';

export interface Transaction {
  id: string;
  alertId: string;
  senderAccountId: string;
  receiverAccountId: string;
  amountVnd: number;
  channel: 'P2P_WALLET' | 'VIETQR' | 'PAYMENT_GATEWAY' | 'VOUCHER_REDEEM';
  message: string;
  deviceId: string;
  hopIndex: number;
  status: TransactionStatus;
  timestamp: string;
  idempotencyKey?: string;
  relatedTxId?: string;
  txKind?: 'P2P_TRANSFER' | 'CLAWBACK_REVERSAL' | 'SEED_FLOW';
}

export interface LedgerEntryRecord {
  id: string;
  txId: string;
  accountId: string;
  entryType: 'DEBIT' | 'CREDIT';
  amountVnd: number;
  currency: 'VND';
  status: 'SETTLED' | 'REVERSED';
  idempotencyKey?: string;
  noteVi?: string;
  createdAt: string;
}

export interface ApiSecurityEvent {
  id: string;
  alertId: string;
  accountId: string;
  endpoint: string;
  concurrentRequests100ms: number;
  hmacSignatureValid: boolean;
  anomalyClass: 'RACE_CONDITION_TOCTOU' | 'WEBHOOK_SPOOF' | 'IDOR_PROBE' | 'NORMAL_TRAFFIC';
  payloadSummary: string;
  timestamp: string;
}

export interface EvidenceArtifact {
  id: string;
  alertId: string;
  kind: 'CHAT_TRANSCRIPT' | 'SCREENSHOT_IMAGE' | 'SMS_SPOOF' | 'WEBHOOK_PAYLOAD' | 'MEDICAL_INVOICE';
  title: string;
  textContent: string;
  imageDataUrl?: string;
  extractedSignals: string[];
  aiMetadata?: AiExecutionMetadata;
}

export interface FraudAlert {
  id: string;
  title: string;
  subtitle: string;
  scenarioCode: ScenarioCode;
  primaryAccountId: string;
  targetRecipientAccountId: string;
  severity: AlertSeverity;
  status: AlertStatus;
  deterministicRiskScore: number;
  tracks: ContestTrack[];
  createdAt: string;
  traditionalRuleReason: string;
}

export interface ForensicToolStep {
  toolName:
    | 'query_account_profile'
    | 'trace_money_flow_graph'
    | 'inspect_cyber_session_logs'
    | 'detect_business_logic_abuse'
    | 'correlate_scam_campaign';
  labelVi: string;
  status: 'SUCCESS' | 'WARNING' | 'CRITICAL';
  durationMs: number;
  summaryVi: string;
  evidenceIds: string[];
  riskContribution: number;
}

export interface RiskAttributionFactor {
  id: string;
  labelVi: string;
  deltaScore: number;
  kind:
    | 'RISK_BOOSTER'
    | 'TRUST_DAMPENER'
    | 'ADAPTIVE_HITL_DAMPENER'
    | 'ADAPTIVE_HITL_BOOSTER';
  metricDetail: string;
}

export type FlowVelocityStatus =
  | 'MEASURED_INTERVAL'
  | 'SINGLE_EVENT_NO_WINDOW'
  | 'ZERO_ELAPSED_TIME'
  | 'INVALID_TIMESTAMP_DATA'
  | 'NO_TRANSACTIONS';

export interface QuantitativeGraphMetrics {
  zScoreDeviation: number;
  flowVelocityVndPerMin: number;
  flowVelocityStatus?: FlowVelocityStatus;
  smurfingEntropyIndex: number;
  deviceBipartiteClusterScore: number;
  crossVictimFanIn: number;
}

export interface GraphNodeItem {
  id: string;
  label: string;
  sublabel: string;
  nodeKind: 'VICTIM' | 'SUSPECT_MULE' | 'SHARED_DEVICE' | 'API_ENDPOINT' | 'TRUSTED_PARTNER';
  riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'SAFE';
  evidenceId?: string;
  metadata: Record<string, string | number | boolean>;
  position: { x: number; y: number };
}

export interface GraphEdgeItem {
  id: string;
  source: string;
  target: string;
  label: string;
  animated: boolean;
  edgeKind: 'MONEY_FLOW' | 'DEVICE_LINK' | 'API_BURST';
  isHighRisk: boolean;
}

export const PlaybookActionSchema = z.object({
  id: z.string().min(1).max(80),
  actionType: z.enum([
    'REVOKE_TOKEN_FAMILY',
    'FREEZE_MULE_ACCOUNTS',
    'ACTIVATE_COMMUNITY_SHIELD',
    'ENFORCE_IDEMPOTENCY_LOCK',
    'CLAWBACK_ILLICIT_CREDIT',
    'MARK_SAFE_FALSE_POSITIVE',
  ]),
  labelVi: z.string().min(1).max(240),
  targetEntityId: z.string().min(1).max(80),
  recommended: z.boolean(),
});

export type PlaybookActionItem = z.infer<typeof PlaybookActionSchema>;

export const GeminiStructuredBriefSchema = z.object({
  classification: z.enum([
    'CONFIRMED_ATO_MULE',
    'CONFIRMED_LOGIC_ABUSE',
    'CONFIRMED_APP_SCAM',
    'FALSE_POSITIVE_SAFE',
  ]),
  confidenceScore: z.number().min(0).max(100),
  executiveSummaryVi: z.string().min(10).max(4000),
  keyFindingsVi: z.array(z.string().max(600)).min(1).max(6),
  citedEvidenceIds: z.array(z.string().max(80)).max(30),
  userShieldWarningVi: z.string().max(1000),
  recommendedActions: z.array(PlaybookActionSchema).min(1).max(12),
});

export type AiExecutionPath =
  | 'PRIMARY_MODEL'
  | 'FALLBACK_MODEL'
  | 'DETERMINISTIC_FALLBACK'
  | 'AI_UNAVAILABLE';

export type AiFallbackReasonCode =
  | 'PROVIDER_UNAVAILABLE'
  | 'RATE_LIMITED'
  | 'QUOTA_EXCEEDED'
  | 'TIMEOUT'
  | 'MODEL_UNAVAILABLE'
  | 'UNCONFIGURED'
  | 'UNKNOWN_PROVIDER_ERROR';

export interface AiExecutionMetadata {
  executionPath: AiExecutionPath;
  primaryModel: string;
  modelUsed: string;
  fallbackReason?: AiFallbackReasonCode;
  userNoticeVi?: string;
}

export interface InvestigationReport {
  alertId: string;
  classification: CaseClassification;
  confidenceScore: number;
  deterministicRiskScore: number;
  executiveSummaryVi: string;
  keyFindingsVi: string[];
  citedEvidenceIds: string[];
  toolTraceSteps: ForensicToolStep[];
  recommendedActions: PlaybookActionItem[];
  userShieldWarningVi: string;
  modelUsed: string;
  aiMetadata?: AiExecutionMetadata;
  latencyMs: number;
  generatedAt: string;
}

export interface ShieldRule {
  id: string;
  alertId: string;
  targetAccountId: string;
  targetAccountNumber: string;
  targetOwnerName: string;
  targetDeviceId?: string;
  ruleType: 'BLOCK_RECIPIENT_MULE' | 'FREEZE_SESSION_FAMILY' | 'RATE_LIMIT_ENDPOINT';
  userWarningVi: string;
  active: boolean;
  createdAt: string;
}

export interface AuditLogEntry {
  id: string;
  alertId: string;
  actor: 'AI_AGENT' | 'OPS_ANALYST' | 'CONSUMER_SHIELD';
  action: string;
  detailsVi: string;
  timestamp: string;
}

export interface StandardCaseInputSpec {
  customTitle?: string;
  // Part 1: Sender & Transaction Profile
  senderName: string;
  senderAccountNumber: string;
  senderAvgTxVnd: number;
  senderKycLevel: 'LEVEL_1' | 'LEVEL_2_BIOMETRIC';
  amountVnd: number;
  splitTxCount: number;
  channel: 'P2P_WALLET' | 'VIETQR' | 'PAYMENT_GATEWAY' | 'VOUCHER_REDEEM';
  // Part 2: Recipient & Network Profile
  recipientAccountNumber: string;
  recipientOwnerName: string;
  bankOrWalletName: string;
  recipientAccountType: AccountType;
  recipientAccountAgeDays: number;
  recipientKycLevel: 'LEVEL_1' | 'LEVEL_2_BIOMETRIC';
  crossVictimFanInCount: number;
  // Part 3: Cyber, Device & Behavioral Telemetry
  deviceIntegrity: 'TRUSTED_PERSONAL_DEVICE' | 'SHARED_EMULATOR_ROOTED' | 'UNRECOGNIZED_FOREIGN_IP';
  sessionSecurity: 'BIOMETRIC_FACEID_PASSED' | 'SESSION_SURVIVED_PASSWORD_RESET' | 'NORMAL_LOGIN';
  inCallCoercionDetected: boolean;
  deepfakeOrVirtualCamDetected?: boolean;
  apiConcurrentRequests100ms: number;
  webhookHmacValid: boolean;
  // Part 4: Multimodal Evidence
  rawTranscript: string;
  imageDataUrl?: string;
}

export type OperatorRole = 'L2_CHECKER' | 'L1_MAKER' | 'END_USER';

export interface WorkspaceNotification {
  id: string;
  titleVi: string;
  detailVi: string;
  severity: 'INFO' | 'SUCCESS' | 'WARNING' | 'CRITICAL';
  timestamp: string;
  read: boolean;
  alertId?: string;
}

export interface SimoReceiptRecord {
  receiptId: string;
  alertId: string;
  dossierId: string;
  complianceStandard: string;
  victimIdentityHashSha256: string;
  victimPseudonymHmacSha256?: string;
  dossierIntegritySha256?: string;
  pushedAt: string;
}

export interface AnalystOverrideRecord {
  alertId: string;
  overriddenTo: 'OVERRIDE_SAFE' | 'FORCE_BLOCK';
  reasonVi: string;
  timestamp: string;
}

export type ClawbackRecoveryStatus = 'RECOVERED' | 'PARTIALLY_RECOVERED' | 'FAILED';

export interface ClawbackReceiptRecord {
  clawbackId: string;
  alertId: string;
  idempotencyKey?: string;
  requestedAmountVnd?: number;
  recoveredAmountVnd: number;
  missingAmountVnd?: number;
  recoveryStatus?: ClawbackRecoveryStatus;
  reversalTxId?: string;
  victimAccountId: string;
  victimOwnerName: string;
  sourceMuleAccountId: string;
  txIds: string[];
  executedAt: string;
}

export interface UrlThreatFinding {
  url: string;
  domain: string;
  isApkPayload: boolean;
  isPlainHttp: boolean;
  typosquattingTarget?: string;
  riskScore: number;
  verdict: 'MALICIOUS_APK_PHISHING' | 'SUSPICIOUS_DOMAIN' | 'SAFE_OFFICIAL';
  reasonVi: string;
}

export type MerchantVisionStatus =
  | 'VERIFIED_LEDGER_MATCH'
  | 'AMOUNT_MISMATCH'
  | 'TRANSACTION_NOT_FOUND'
  | 'NOT_SETTLED'
  | 'RECIPIENT_MISMATCH'
  | 'NEEDS_MANUAL_REVIEW'
  | 'INVALID_IMAGE'
  | 'AI_UNAVAILABLE'
  | 'AMBIGUOUS_EXTRACTION';

export interface MerchantVisionExtractedFields {
  claimedTransactionId: string | null;
  claimedAmountVnd: number | null;
  currency: string;
  claimedRecipientAccount: string | null;
  claimedRecipientName: string | null;
  claimedSenderInfo: string | null;
  claimedTransactionTime: string | null;
  paymentProvider: string | null;
  otherReferences: string[];
  detectedAmountsCount: number;
  candidateTransactionIds: string[];
  imageQualityStatus: 'CLEAR' | 'BLURRY' | 'CROPPED' | 'ROTATED' | 'UNREADABLE';
  fieldConfidence: {
    transactionId: number;
    amountVnd: number;
    recipientAccount: number;
    overall: number;
  };
  extractionWarnings: string[];
  missingFields: string[];
  suspiciousVisualIndicators: string[];
}

export interface MerchantVisionVerificationBundle {
  status: MerchantVisionStatus;
  verificationSource: 'AI_OCR_AND_LEDGER' | 'MANUAL_AND_LEDGER' | 'SECURITY_GATE';
  extractedFields: MerchantVisionExtractedFields | null;
  ledgerComparison: {
    foundInLedger: boolean;
    txId: string | null;
    ledgerStatus: string;
    actualAmountVnd: number;
    claimedAmountVnd: number | null;
    expectedMerchantAccountId?: string;
    actualReceiverAccountId?: string;
    matchedSenderName?: string;
    soundboxAnnouncementVi?: string;
  };
  matchedFields: string[];
  mismatchedFields: string[];
  reasonsVi: string[];
  warningsVi: string[];
  recommendedNextActionVi: string;
  confidenceNoteVi: string;
  modelUsed: string;
  aiMetadata?: AiExecutionMetadata;
  latencyMs: number;
}

export type HitlFeedbackTargetScope = 'ALERT_CASE' | 'RECIPIENT_PATTERN' | 'TX_PATTERN';
export type HitlFeedbackDecision = 'OVERRIDE_SAFE' | 'FORCE_BLOCK';
export type HitlFeedbackLifecycleStatus =
  | 'PENDING_APPROVAL'
  | 'APPROVED_ACTIVE'
  | 'REJECTED'
  | 'EXPIRED'
  | 'REVOKED';

export type HitlFeedbackReasonCode =
  | 'VERIFIED_LEGITIMATE_PARTNER'
  | 'FALSE_POSITIVE_CONTEXT'
  | 'CONFIRMED_MULE_PATTERN'
  | 'MERCHANT_BILL_FRAUD'
  | 'ANALYST_ESCALATION';

export interface HitlFeedbackMemoryRecord {
  feedbackId: string;
  sourceAlertId: string;
  targetScope: HitlFeedbackTargetScope;
  targetFingerprint: string;
  hmacKeyVersion?: string;
  targetDisplayLabel: string;
  recipientAccountId?: string;
  contextSignature: string;
  feedbackDecision: HitlFeedbackDecision;
  reasonCode: HitlFeedbackReasonCode;
  analystRationale: string;
  evidenceReferences: string[];
  actorPrincipalId: string;
  actorRole: OperatorRole;
  approvedByPrincipalId?: string;
  approvedAt?: string;
  rejectedReasonVi?: string;
  revokedByPrincipalId?: string;
  revokedAt?: string;
  createdAt: string;
  expiresAt: string;
  status: HitlFeedbackLifecycleStatus;
  riskAdjustment: number;
  memoryVersion: number;
}

export interface AdaptiveFeedbackSummary {
  appliedRecords: Array<{
    feedbackId: string;
    feedbackDecision: HitlFeedbackDecision;
    targetScope: HitlFeedbackTargetScope;
    riskAdjustment: number;
    reasonCode: HitlFeedbackReasonCode;
    explanationVi: string;
  }>;
  conflictDetected: boolean;
  needsReviewVi?: string;
  hardRuleBlockedOverride: boolean;
  hardRuleNoticeVi?: string;
  baseScoreBeforeFeedback: number;
  finalScoreAfterFeedback: number;
}

export interface IdempotencyTransferRecord {
  idempotencyKey: string;
  txId: string;
  requestSignature: string;
  canonicalPayload: {
    senderAccountId: string;
    receiverAccountId: string;
    recipientAccountIdOrNumber: string;
    amountVnd: number;
    message: string;
  };
  decisionSnapshot: ConsumerTransferDecision;
  senderBalanceVnd: number;
  receiverBalanceVnd: number | null;
  recordedAt: string;
}

export interface SessionDeltaSnapshot {
  sessionId: string;
  stateRevision?: number;
  deltaIntegrityTag?: string;
  makerPrincipalByAlertId?: Record<string, string>;
  alertStatuses: Record<string, AlertStatus>;
  pendingL2ApprovalAlertIds?: string[];
  frozenAccountIds: string[];
  activeShieldRules: ShieldRule[];
  selfRescuedAmountVnd?: number;
  analystFeedbackCount?: number;
  analystOverridesByAlertId?: Record<string, AnalystOverrideRecord>;
  hitlFeedbackMemory?: HitlFeedbackMemoryRecord[];
  simoAckReceipts?: SimoReceiptRecord[];
  clawbackReceipts?: ClawbackReceiptRecord[];
  ledgerEntries?: LedgerEntryRecord[];
  processedIdempotencyKeys?: Record<string, string>;
  idempotencyRecordsByKey?: Record<string, IdempotencyTransferRecord>;
  reportsByAlertId: Record<string, InvestigationReport>;
  customAlerts: FraudAlert[];
  customAccounts: Account[];
  customTransactions: Transaction[];
  customEvidences: EvidenceArtifact[];
  customDevices?: DeviceFingerprint[];
  customAuthLogs?: AuthSessionLog[];
  customApiEvents?: ApiSecurityEvent[];
  customInputSpecsByAlertId?: Record<string, StandardCaseInputSpec>;
  auditLogs: AuditLogEntry[];
  updatedAt: string;
}

export interface ForensicSuiteOutput {
  alertId: string;
  deterministicRiskScore: number;
  validEvidenceIds: string[];
  evidenceLabelMap: Record<string, string>;
  toolTraceSteps: ForensicToolStep[];
  riskAttributionFactors: RiskAttributionFactor[];
  quantitativeMetrics: QuantitativeGraphMetrics;
  graphNodes: GraphNodeItem[];
  graphEdges: GraphEdgeItem[];
  urlThreatFindings?: UrlThreatFinding[];
  adaptiveFeedbackSummary?: AdaptiveFeedbackSummary;
  fallbackReport: InvestigationReport;
}

export interface ConsumerTransferRequest {
  senderAccountId?: string;
  senderName: string;
  recipientAccountIdOrNumber: string;
  amountVnd: number;
  message: string;
  idempotencyKey?: string;
}

export interface PsychologicalDeEscalationCard {
  archetypeTitleVi: string;
  manipulationTacticVi: string;
  realityChecklistVi: string[];
  emergencyHotlineVi: string;
}

export interface ConsumerTransferDecision {
  decision: 'BLOCKED_BY_SHIELD' | 'WARN_COOLING_OFF' | 'ALLOWED_SAFE';
  matchedRuleId?: string;
  transactionId?: string;
  transactionStatus?: TransactionStatus;
  senderAccountId?: string;
  recipientAccountId?: string;
  recipientAccountNumber: string;
  recipientName: string;
  amountVnd: number;
  senderBalanceVnd?: number;
  receiverBalanceVnd?: number;
  idempotentReplay?: boolean;
  titleVi: string;
  explanationVi: string;
  coolingOffQuestionsVi: string[];
  deEscalationCardVi?: PsychologicalDeEscalationCard;
  responseTimeMs: number;
}

export type TrustLightColor = 'GREEN' | 'YELLOW' | 'RED';

export interface RecipientTrustStatus {
  color: TrustLightColor;
  badgeVi: string;
  headlineVi: string;
  detailVi: string;
  sourceTag: string;
}

export interface CrossCaseLink {
  alertId: string;
  linkedAlertIds: string[];
  sharedInfrastructureIds: string[];
  triageActionHint: 'CLUSTER_HIGH_PRIORITY' | 'ISOLATED_CRITICAL' | 'AUTO_CLEAR_SAFE_FP';
  summaryVi: string;
}
