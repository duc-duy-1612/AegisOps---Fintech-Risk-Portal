import { sha256Hex } from './crypto-hash';
import type {
  Account,
  AuditLogEntry,
  AuthSessionLog,
  DeviceFingerprint,
  ForensicSuiteOutput,
  FraudAlert,
  InvestigationReport,
  Transaction,
} from './types';

export type Qd2345CustomerType = 'INDIVIDUAL' | 'ORGANIZATION';

export type Qd2345TransactionCategory =
  | 'INTERPERSONAL_P2P_AND_VIETQR_TRANSFER'
  | 'LINKED_WALLET_TOPUP_WITHDRAW_OWN_ACCOUNT'
  | 'GOODS_SERVICES_PAYMENT_LEGAL_MERCHANT'
  | 'SELF_OWNED_SAME_BANK_TRANSFER'
  | 'FIRST_TIME_OR_NEW_DEVICE_ACTIVATION'
  | 'ORGANIZATIONAL_ACCOUNT_TRANSACTION';

export type Qd2345AuthenticationCategory =
  | 'NONE'
  | 'TYPE_A_BASIC'
  | 'TYPE_B_OTP'
  | 'TYPE_C_BIOMETRIC'
  | 'TYPE_D_BIOMETRIC_HIGH_VALUE'
  | 'TYPE_ORG_DIGITAL_SIGNATURE';

export type BiometricVerificationStatus =
  | 'NOT_REQUIRED'
  | 'REQUIRED'
  | 'VERIFIED'
  | 'FAILED'
  | 'NOT_IMPLEMENTED_IN_DEMO';

export type RegulatoryControlStatus =
  | 'REQUIREMENT_MAPPED'
  | 'SIMULATED_SIGNAL'
  | 'NOT_IMPLEMENTED'
  | 'CERTIFICATION_NOT_VERIFIED';

export interface Qd2345DailyHistoryEvent {
  amountVnd: number;
  timestamp: string;
  authenticationCategory?: Qd2345AuthenticationCategory;
}

export interface Qd2345EvaluationInput {
  customerType?: Qd2345CustomerType;
  transactionCategory?: Qd2345TransactionCategory;
  singleTransactionAmountVnd?: number;
  dailyPriorTransactions?: readonly Qd2345DailyHistoryEvent[];
  isFirstTimeOrNewDevice?: boolean;
  hasObservedBiometricPass?: boolean;
  hasObservedBiometricFailure?: boolean;
  biometricEvidenceIds?: readonly string[];
  hasAuthTelemetry?: boolean;
}

export interface Qd2345ComplianceAssessment {
  decisionReference: '2345/QĐ-NHNN';
  mappingStatus: 'REQUIREMENT_MAPPED';
  customerType: Qd2345CustomerType;
  transactionCategory: Qd2345TransactionCategory;
  singleTransactionAmountVnd: number | null;
  dailyAccumulatedTotalTVnd: number | null;
  dailyAccumulatedUnauthenticatedTksthVnd: number | null;
  applicableSingleTxThresholdVnd: number | null;
  applicableDailyTksthThresholdVnd: number | null;
  applicableAuthenticationCategory: Qd2345AuthenticationCategory;
  firstTimeOrNewDeviceTriggered: boolean;
  biometricVerificationRequired: boolean;
  biometricVerificationStatus: BiometricVerificationStatus;
  biometricVerificationEvidence: string[];
  requirementReasonVi: string;
  missingInputFields: string[];
}

export interface Tt77Article8Clause4Control {
  indicator:
  | 'debuggerAttached'
  | 'emulatorOrVirtualMachine'
  | 'adbEnabled'
  | 'runtimeHooking'
  | 'appRepackagingOrTampering'
  | 'rootOrJailbreak'
  | 'bootloaderUnlocked';
  labelVi: string;
  status: 'SIMULATED_SIGNAL' | 'NOT_IMPLEMENTED';
  simulatedDetected: boolean;
  noteVi: string;
}

export interface Tt77ComplianceAssessment {
  circularReference: '77/2025/TT-NHNN';
  consolidatedCircularReference: '50/2024/TT-NHNN (sửa đổi, bổ sung bởi 77/2025/TT-NHNN)';
  article8Clause4: {
    amendingProvisionRef: string;
    mappingStatus: 'REQUIREMENT_MAPPED';
    simulatedAnomalyPresent: boolean;
    controls: Tt77Article8Clause4Control[];
    browserLimitationDisclaimerVi: string;
  };
  article11Clause5cPad: {
    amendingProvisionRef: string;
    mappingStatus: 'REQUIREMENT_MAPPED';
    standardReference: 'ISO/IEC 30107-3 Level 2 (or equivalent certified PAD)';
    certificationStatus: 'CERTIFICATION_NOT_VERIFIED';
    telemetryStatus: 'SIMULATED_SIGNAL' | 'NOT_IMPLEMENTED';
    simulatedPadAttackDetected: boolean;
    evidenceIds: string[];
    disclaimerVi: string;
  };
}

export interface SimoPiiMaskedReport {
  schemaVersion: string;
  reportingInstitution: string;
  complianceStandard: string;
  victimAccountMasked: string;
  victimIdentityHashSha256: string;
  piiPseudonymizationMode: 'CLIENT_UNKEYED_SHA256_PREVIEW' | 'SERVER_HMAC_SHA256_KEYED';
  flaggedMuleAccountNumber: string;
  flaggedDeviceId: string | null;
  flaggedDeviceFingerprintHash: string | null;
  dossierIntegrityHashSha256: string;
  riskClassification: string;
  deterministicRiskScore: number;
  q2345BiometricThresholdTriggered: boolean;
  biometricVerificationRequired: boolean;
  biometricVerificationStatus: BiometricVerificationStatus;
  biometricVerificationEvidence: string[];
  tt50DeviceIntegrityViolation: boolean;
  tt77Article8MappingStatus: RegulatoryControlStatus;
  tt77PadCertificationStatus: 'CERTIFICATION_NOT_VERIFIED';
}

export interface ComplianceIncidentDossier {
  dossierId: string;
  alertId: string;
  generatedAt: string;
  severity: FraudAlert['severity'];
  status: FraudAlert['status'];
  classification: InvestigationReport['classification'];
  deterministicRiskScore: number;
  confidenceScore: number;
  primaryAccountId: string;
  targetRecipientAccountId: string;
  modelUsed: string;
  executiveSummaryVi: string;
  regulatoryReferencesVi: string[];
  geminiDataTransmissionDisclosureVi: string;
  qd2345Assessment: Qd2345ComplianceAssessment;
  tt77Assessment: Tt77ComplianceAssessment;
  simoPiiMaskedPayload: SimoPiiMaskedReport;
  verifiedEvidenceList: Array<{ id: string; description: string }>;
  forensicStepsSummary: Array<{ toolName: string; labelVi: string; status: string; summaryVi: string }>;
  executedActionsVi: string[];
  auditTrailSummary: string[];
  markdownText: string;
}

const QD2345_INDIVIDUAL_TRANSFER_SINGLE_VND = 10_000_000;
const QD2345_INDIVIDUAL_TRANSFER_DAILY_TKSTH_VND = 20_000_000;
const QD2345_INDIVIDUAL_MERCHANT_PAYMENT_SINGLE_VND = 100_000_000;
const QD2345_INDIVIDUAL_MERCHANT_PAYMENT_DAILY_VND = 100_000_000;

const isBiometricAuthCategory = (cat?: Qd2345AuthenticationCategory): boolean =>
  cat === 'TYPE_C_BIOMETRIC' || cat === 'TYPE_D_BIOMETRIC_HIGH_VALUE';

/**
 * Evaluates QĐ 2345/QĐ-NHNN transaction classification, G / T / T_ksth thresholds,
 * and strictly separates requirement-triggered from biometric execution/verification status.
 */
export const evaluateQd2345Compliance = (
  input: Qd2345EvaluationInput
): Qd2345ComplianceAssessment => {
  const missingInputFields: string[] = [];
  const customerType: Qd2345CustomerType = input.customerType ?? 'INDIVIDUAL';

  let transactionCategory: Qd2345TransactionCategory;
  if (customerType === 'ORGANIZATION') {
    transactionCategory =
      input.transactionCategory ?? 'ORGANIZATIONAL_ACCOUNT_TRANSACTION';
  } else {
    transactionCategory =
      input.transactionCategory ?? 'INTERPERSONAL_P2P_AND_VIETQR_TRANSFER';
  }

  const hasAmount =
    typeof input.singleTransactionAmountVnd === 'number' &&
    Number.isFinite(input.singleTransactionAmountVnd) &&
    input.singleTransactionAmountVnd >= 0;
  const G = hasAmount ? Math.round(input.singleTransactionAmountVnd!) : null;
  if (!hasAmount) {
    missingInputFields.push('singleTransactionAmountVnd');
  }

  const priorEvents = [...(input.dailyPriorTransactions ?? [])].sort((a, b) => {
    const aMs = Date.parse(a.timestamp);
    const bMs = Date.parse(b.timestamp);
    if (!Number.isFinite(aMs) || !Number.isFinite(bMs)) return 0;
    return aMs - bMs;
  });

  // Compute daily T (total daily volume) and T_ksth (accumulated unauthenticated volume since last biometric auth)
  let priorTotalT = 0;
  let priorTksth = 0;
  for (const evt of priorEvents) {
    const amt = Math.max(0, Math.round(evt.amountVnd || 0));
    priorTotalT += amt;
    if (isBiometricAuthCategory(evt.authenticationCategory)) {
      // QĐ 2345 Appendix 01: T_ksth resets to 0 after a transaction authenticated by biometric category (C/D)
      priorTksth = 0;
    } else {
      priorTksth += amt;
    }
  }

  const T = G !== null ? priorTotalT + G : null;
  const T_ksth = G !== null ? priorTksth + G : null;
  const firstTimeOrNewDeviceTriggered =
    Boolean(input.isFirstTimeOrNewDevice) ||
    transactionCategory === 'FIRST_TIME_OR_NEW_DEVICE_ACTIVATION';

  let applicableSingleTxThresholdVnd: number | null = null;
  let applicableDailyTksthThresholdVnd: number | null = null;
  let biometricVerificationRequired = false;
  let applicableAuthenticationCategory: Qd2345AuthenticationCategory = 'TYPE_B_OTP';
  let requirementReasonVi = '';

  if (customerType === 'ORGANIZATION' || transactionCategory === 'ORGANIZATIONAL_ACCOUNT_TRANSACTION') {
    // QĐ 2345 Appendix 01 Part II: Organizational customers follow corporate digital signature / multi-level auth rules,
    // NOT individual consumer wallet 10M / 20M biometric thresholds.
    applicableAuthenticationCategory = 'TYPE_ORG_DIGITAL_SIGNATURE';
    biometricVerificationRequired = false;
    requirementReasonVi =
      'Khách hàng Tổ chức áp dụng quy tắc xác thực doanh nghiệp / chữ ký số theo Phần II Phụ lục 01 QĐ 2345/QĐ-NHNN (không gộp chung ngưỡng sinh trắc học 10M/20M của khách hàng cá nhân).';
  } else if (firstTimeOrNewDeviceTriggered) {
    applicableAuthenticationCategory = 'TYPE_C_BIOMETRIC';
    biometricVerificationRequired = true;
    requirementReasonVi =
      'Giao dịch lần đầu trên ứng dụng hoặc thực hiện trên thiết bị mới bắt buộc xác thực sinh trắc học theo Điều 1 & Phụ lục 01 QĐ 2345/QĐ-NHNN bất kể giá trị G.';
  } else if (transactionCategory === 'SELF_OWNED_SAME_BANK_TRANSFER') {
    applicableAuthenticationCategory = 'TYPE_A_BASIC';
    biometricVerificationRequired = false;
    requirementReasonVi =
      'Chuyển tiền giữa các tài khoản cùng chủ sở hữu tại cùng tổ chức không áp dụng ngưỡng sinh trắc học 10M/20M.';
  } else if (transactionCategory === 'GOODS_SERVICES_PAYMENT_LEGAL_MERCHANT') {
    applicableSingleTxThresholdVnd = QD2345_INDIVIDUAL_MERCHANT_PAYMENT_SINGLE_VND;
    applicableDailyTksthThresholdVnd = QD2345_INDIVIDUAL_MERCHANT_PAYMENT_DAILY_VND;
    const exceedsSingle = G !== null && G > QD2345_INDIVIDUAL_MERCHANT_PAYMENT_SINGLE_VND;
    const exceedsDaily = T_ksth !== null && T_ksth > QD2345_INDIVIDUAL_MERCHANT_PAYMENT_DAILY_VND;
    biometricVerificationRequired = exceedsSingle || exceedsDaily;
    applicableAuthenticationCategory = biometricVerificationRequired ? 'TYPE_C_BIOMETRIC' : 'TYPE_B_OTP';
    requirementReasonVi = biometricVerificationRequired
      ? `Thanh toán hàng hóa/dịch vụ cho đơn vị hợp pháp vượt ngưỡng 100 triệu VNĐ (G=${G?.toLocaleString('vi-VN')} ₫, T_ksth=${T_ksth?.toLocaleString('vi-VN')} ₫) → Yêu cầu xác thực sinh trắc học.`
      : `Thanh toán hàng hóa/dịch vụ cho đơn vị hợp pháp không vượt ngưỡng 100 triệu VNĐ (G=${G?.toLocaleString('vi-VN') ?? 'N/A'} ₫, T_ksth=${T_ksth?.toLocaleString('vi-VN') ?? 'N/A'} ₫) → Không bắt buộc sinh trắc học theo nhóm thanh toán.`;
  } else {
    // INTERPERSONAL_P2P_AND_VIETQR_TRANSFER or LINKED_WALLET_TOPUP_WITHDRAW_OWN_ACCOUNT (Individual L3)
    applicableSingleTxThresholdVnd = QD2345_INDIVIDUAL_TRANSFER_SINGLE_VND;
    applicableDailyTksthThresholdVnd = QD2345_INDIVIDUAL_TRANSFER_DAILY_TKSTH_VND;
    const exceedsSingle = G !== null && G > QD2345_INDIVIDUAL_TRANSFER_SINGLE_VND;
    const exceedsDaily = T_ksth !== null && T_ksth > QD2345_INDIVIDUAL_TRANSFER_DAILY_TKSTH_VND;
    biometricVerificationRequired = exceedsSingle || exceedsDaily;
    applicableAuthenticationCategory = biometricVerificationRequired
      ? G !== null && G > 500_000_000
        ? 'TYPE_D_BIOMETRIC_HIGH_VALUE'
        : 'TYPE_C_BIOMETRIC'
      : 'TYPE_B_OTP';
    requirementReasonVi = biometricVerificationRequired
      ? `Chuyển tiền cá nhân (${transactionCategory}) vượt ngưỡng QĐ 2345 (G=${G?.toLocaleString('vi-VN')} ₫ > 10M hoặc T_ksth=${T_ksth?.toLocaleString('vi-VN')} ₫ > 20M) → Yêu cầu xác thực sinh trắc học (Loại ${applicableAuthenticationCategory}).`
      : G === null
        ? 'Thiếu dữ liệu số tiền giao dịch G để xác định ngưỡng QĐ 2345 (không tự động đánh dấu đã vượt ngưỡng).'
        : `Chuyển tiền cá nhân (G=${G.toLocaleString('vi-VN')} ₫ ≤ 10M và T_ksth=${T_ksth?.toLocaleString('vi-VN')} ₫ ≤ 20M) → Chưa vượt ngưỡng bắt buộc sinh trắc học QĐ 2345.`;
  }

  const biometricVerificationEvidence = Array.from(new Set(input.biometricEvidenceIds ?? []));
  const hasAuthTelemetry = input.hasAuthTelemetry ?? (
    Boolean(input.hasObservedBiometricPass) ||
    Boolean(input.hasObservedBiometricFailure) ||
    biometricVerificationEvidence.length > 0
  );

  // D2: Strictly distinguish Requirement from Execution/Verification Status
  let biometricVerificationStatus: BiometricVerificationStatus;
  if (input.hasObservedBiometricFailure) {
    biometricVerificationStatus = 'FAILED';
  } else if (input.hasObservedBiometricPass && biometricVerificationEvidence.length > 0) {
    biometricVerificationStatus = 'VERIFIED';
  } else if (!biometricVerificationRequired) {
    biometricVerificationStatus = 'NOT_REQUIRED';
  } else if (!hasAuthTelemetry) {
    biometricVerificationStatus = 'NOT_IMPLEMENTED_IN_DEMO';
    missingInputFields.push('authLogs.biometricVerificationEvidence');
  } else {
    biometricVerificationStatus = 'REQUIRED';
  }

  return {
    decisionReference: '2345/QĐ-NHNN',
    mappingStatus: 'REQUIREMENT_MAPPED',
    customerType,
    transactionCategory,
    singleTransactionAmountVnd: G,
    dailyAccumulatedTotalTVnd: T,
    dailyAccumulatedUnauthenticatedTksthVnd: T_ksth,
    applicableSingleTxThresholdVnd,
    applicableDailyTksthThresholdVnd,
    applicableAuthenticationCategory,
    firstTimeOrNewDeviceTriggered,
    biometricVerificationRequired,
    biometricVerificationStatus,
    biometricVerificationEvidence,
    requirementReasonVi,
    missingInputFields,
  };
};

/**
 * Maps Circular 50/2024/TT-NHNN as amended and supplemented by Circular 77/2025/TT-NHNN
 * (effective 2026-03-01):
 * - Article 5 of Circular 77/2025/TT-NHNN amending Article 8 (Clause 4) of Circular 50/2024/TT-NHNN
 *   (Mobile Banking anti-tampering / automatic stop controls).
 * - Article 7 of Circular 77/2025/TT-NHNN amending Article 11 (Point c, Clause 5) of Circular 50/2024/TT-NHNN
 *   (ISO 30107 Level 2 PAD certification by FIDO Alliance-accredited lab or IAF MLA Certification Body).
 * Transparently marks browser limitations and CERTIFICATION_NOT_VERIFIED without overclaiming.
 */
export const evaluateTt77Compliance = (params: {
  devices?: readonly DeviceFingerprint[];
  authLogs?: readonly AuthSessionLog[];
  flaggedDeviceId?: string | null;
}): Tt77ComplianceAssessment => {
  const devices = params.devices ?? [];
  const authLogs = params.authLogs ?? [];

  const relevantDevices = params.flaggedDeviceId
    ? devices.filter((d) => d.id === params.flaggedDeviceId)
    : devices;
  const simulatedEmulatorOrRooted = relevantDevices.some((d) => d.isEmulatorOrRooted);
  const simulatedRootKeyword = relevantDevices.some((d) =>
    /root|jailbreak/i.test(d.osBrowser)
  );
  const simulatedEmulatorKeyword = relevantDevices.some((d) =>
    /emulator|ldplayer|vm|headless|bot/i.test(d.osBrowser)
  );

  const controls: Tt77Article8Clause4Control[] = [
    {
      indicator: 'debuggerAttached',
      labelVi: 'Phát hiện trình gỡ lỗi (Debugger)',
      status: 'NOT_IMPLEMENTED',
      simulatedDetected: false,
      noteVi: 'Yêu cầu SDK native di động (iOS/Android); bản demo web không đo trực tiếp trạng thái debugger OS.',
    },
    {
      indicator: 'emulatorOrVirtualMachine',
      labelVi: 'Phát hiện máy giả lập / máy ảo / thiết bị giả mạo',
      status: simulatedEmulatorOrRooted || simulatedEmulatorKeyword ? 'SIMULATED_SIGNAL' : 'NOT_IMPLEMENTED',
      simulatedDetected: simulatedEmulatorOrRooted || simulatedEmulatorKeyword,
      noteVi:
        simulatedEmulatorOrRooted || simulatedEmulatorKeyword
          ? 'Tín hiệu mô phỏng từ hồ sơ kịch bản/telemetry thiết bị (không phải đo trực tiếp phần cứng trên trình duyệt).'
          : 'Không có tín hiệu mô phỏng máy giả lập; cần Mobile RASP SDK để đo thực tế.',
    },
    {
      indicator: 'adbEnabled',
      labelVi: 'Phát hiện bật Android Debug Bridge (ADB)',
      status: 'NOT_IMPLEMENTED',
      simulatedDetected: false,
      noteVi: 'Trình duyệt web không có quyền truy vấn trạng thái ADB của hệ điều hành Android.',
    },
    {
      indicator: 'runtimeHooking',
      labelVi: 'Phát hiện chèn mã / Hooking (Frida, Xposed...)',
      status: 'NOT_IMPLEMENTED',
      simulatedDetected: false,
      noteVi: 'Yêu cầu kiểm tra runtime native (anti-hooking SDK); chưa triển khai trong bản demo trình duyệt.',
    },
    {
      indicator: 'appRepackagingOrTampering',
      labelVi: 'Phát hiện đóng gói lại / chỉnh sửa ứng dụng (Repackaging / Tampering)',
      status: 'NOT_IMPLEMENTED',
      simulatedDetected: false,
      noteVi: 'Yêu cầu xác thực chữ ký nhị phân ứng dụng (App Attest / Play Integrity) ở tầng mobile native.',
    },
    {
      indicator: 'rootOrJailbreak',
      labelVi: 'Phát hiện thiết bị đã Root / Jailbreak',
      status: simulatedRootKeyword || simulatedEmulatorOrRooted ? 'SIMULATED_SIGNAL' : 'NOT_IMPLEMENTED',
      simulatedDetected: simulatedRootKeyword || simulatedEmulatorOrRooted,
      noteVi:
        simulatedRootKeyword || simulatedEmulatorOrRooted
          ? 'Tín hiệu mô phỏng từ metadata thiết bị trong kịch bản điều tra (không phải quét root/jailbreak thực tế từ trình duyệt).'
          : 'Không đo trực tiếp trạng thái root/jailbreak trên trình duyệt.',
    },
    {
      indicator: 'bootloaderUnlocked',
      labelVi: 'Phát hiện mở khóa Bootloader',
      status: 'NOT_IMPLEMENTED',
      simulatedDetected: false,
      noteVi: 'Chỉ kiểm chứng được thông qua Hardware Attestation trên thiết bị di động native.',
    },
  ];

  const padFailureLogs = authLogs.filter(
    (l) => l.eventType === 'DEEPFAKE_VIRTUAL_CAM_INJECTION'
  );
  const biometricPassLogs = authLogs.filter(
    (l) => l.eventType === 'BIOMETRIC_STEP_UP_PASS'
  );
  const padEvidenceIds = [...padFailureLogs, ...biometricPassLogs].map((l) => l.id);
  const hasSimulatedPadTelemetry = padEvidenceIds.length > 0;

  return {
    circularReference: '77/2025/TT-NHNN',
    consolidatedCircularReference: '50/2024/TT-NHNN (sửa đổi, bổ sung bởi 77/2025/TT-NHNN)',
    article8Clause4: {
      amendingProvisionRef:
        'Điều 5 Thông tư 77/2025/TT-NHNN sửa đổi, bổ sung Khoản 4 Điều 8 Thông tư 50/2024/TT-NHNN (hiệu lực 01/03/2026)',
      mappingStatus: 'REQUIREMENT_MAPPED',
      simulatedAnomalyPresent: controls.some((c) => c.simulatedDetected),
      controls,
      browserLimitationDisclaimerVi:
        'AegisOps bản demo chạy trên trình duyệt web nên CHỈ ánh xạ yêu cầu Khoản 4 Điều 8 Thông tư 50/2024/TT-NHNN (sửa đổi bởi Điều 5 Thông tư 77/2025/TT-NHNN) và hiển thị tín hiệu mô phỏng (SIMULATED_SIGNAL), KHÔNG tuyên bố phát hiện trực tiếp root/jailbreak/ADB/hook/bootloader từ phần cứng thiết bị.',
    },
    article11Clause5cPad: {
      amendingProvisionRef:
        'Điều 7 Thông tư 77/2025/TT-NHNN sửa đổi, bổ sung Điểm c Khoản 5 Điều 11 Thông tư 50/2024/TT-NHNN (hiệu lực 01/03/2026)',
      mappingStatus: 'REQUIREMENT_MAPPED',
      standardReference: 'ISO/IEC 30107-3 Level 2 (or equivalent certified PAD)',
      certificationStatus: 'CERTIFICATION_NOT_VERIFIED',
      telemetryStatus: hasSimulatedPadTelemetry ? 'SIMULATED_SIGNAL' : 'NOT_IMPLEMENTED',
      simulatedPadAttackDetected: padFailureLogs.length > 0,
      evidenceIds: padEvidenceIds,
      disclaimerVi:
        'Ánh xạ yêu cầu Điểm c Khoản 5 Điều 11 Thông tư 50/2024/TT-NHNN (sửa đổi bởi Điều 7 Thông tư 77/2025/TT-NHNN) về giải pháp chống giả mạo sinh trắc học (PAD đạt chuẩn ISO 30107 Level 2 hoặc tương đương do phòng thí nghiệm được FIDO Alliance hoặc Tổ chức chứng nhận thuộc IAF MLA công nhận). AegisOps KHÔNG có chứng chỉ kiểm định ISO 30107 Level 2 (CERTIFICATION_NOT_VERIFIED) và chỉ mô phỏng tín hiệu PAD.',
    },
  };
};

/**
 * Pure Domain Generator for Fintech Compliance & Regulatory Incident Dossier
 * Aligned with SBV Decision 2345/QĐ-NHNN, Circular 50/2024/TT-NHNN (as amended by Circular 77/2025/TT-NHNN),
 * Law 91/2025/QH15 & Decree 356/2025/NĐ-CP (replacing repealed Decree 13/2023/NĐ-CP effective 2026-01-01) & SIMO.
 * Distinguishes SHA-256 integrity digests and keyed HMAC-SHA-256 pseudonymization from anonymization/encryption.
 */
export const buildComplianceIncidentDossier = (params: {
  alert: FraudAlert;
  forensics: ForensicSuiteOutput;
  report?: InvestigationReport | null;
  auditLogs: readonly AuditLogEntry[];
  accounts?: readonly Account[];
  transactions?: readonly Transaction[];
  authLogs?: readonly AuthSessionLog[];
  devices?: readonly DeviceFingerprint[];
  qd2345Context?: Qd2345EvaluationInput;
}): ComplianceIncidentDossier => {
  const activeReport = params.report ?? params.forensics.fallbackReport;
  const validSet = new Set(params.forensics.validEvidenceIds);

  const verifiedIds = activeReport.citedEvidenceIds.filter((id) => validSet.has(id));
  const finalEvidenceIds =
    verifiedIds.length > 0 ? verifiedIds : params.forensics.validEvidenceIds.slice(0, 5);

  const verifiedEvidenceList = finalEvidenceIds.map((id) => ({
    id,
    description: params.forensics.evidenceLabelMap[id] ?? `Bản ghi xác thực ${id}`,
  }));

  const alertAuditLogs = params.auditLogs.filter(
    (l) => l.alertId === params.alert.id || l.alertId.includes(params.alert.id)
  );

  const executedActionsVi = activeReport.recommendedActions.map((a) => a.labelVi);
  const auditTrailSummary =
    alertAuditLogs.length > 0
      ? alertAuditLogs.map((a) => `[${a.actor}] ${a.action}: ${a.detailsVi}`)
      : ['[SYSTEM] Hồ sơ khởi tạo tự động từ bộ công cụ Deterministic Forensics.'];

  const sharedDeviceNode = params.forensics.graphNodes.find(
    (node) => node.nodeKind === 'SHARED_DEVICE'
  );
  const flaggedDeviceId = sharedDeviceNode ? sharedDeviceNode.id : null;

  // Derive QĐ 2345 inputs from real alert transactions/accounts/authLogs when provided
  const alertTxs = (params.transactions ?? []).filter((t) => t.alertId === params.alert.id);
  const primaryAccount = (params.accounts ?? []).find((a) => a.id === params.alert.primaryAccountId);
  const targetAccount = (params.accounts ?? []).find(
    (a) => a.id === params.alert.targetRecipientAccountId
  );
  const primaryAuthLogs = (params.authLogs ?? []).filter(
    (l) => l.accountId === params.alert.primaryAccountId
  );

  const sortedAlertTxs = [...alertTxs].sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp));
  const latestAlertTx = sortedAlertTxs[sortedAlertTxs.length - 1];
  const priorSameDayTxs: Qd2345DailyHistoryEvent[] = sortedAlertTxs.slice(0, -1).map((t) => ({
    amountVnd: t.amountVnd,
    timestamp: t.timestamp,
    authenticationCategory: 'TYPE_B_OTP',
  }));

  const inferredCustomerType: Qd2345CustomerType =
    params.qd2345Context?.customerType ??
    (primaryAccount?.accountType === 'MERCHANT' ||
      primaryAccount?.accountType === 'TRUSTED_INSTITUTION'
      ? 'ORGANIZATION'
      : 'INDIVIDUAL');

  const inferredCategory: Qd2345TransactionCategory =
    params.qd2345Context?.transactionCategory ??
    (inferredCustomerType === 'ORGANIZATION'
      ? 'ORGANIZATIONAL_ACCOUNT_TRANSACTION'
      : targetAccount?.accountType === 'TRUSTED_INSTITUTION' &&
        latestAlertTx?.channel === 'PAYMENT_GATEWAY'
        ? 'GOODS_SERVICES_PAYMENT_LEGAL_MERCHANT'
        : 'INTERPERSONAL_P2P_AND_VIETQR_TRANSFER');

  const biometricPassLogs = primaryAuthLogs.filter(
    (l) => l.eventType === 'BIOMETRIC_STEP_UP_PASS'
  );
  const biometricFailLogs = primaryAuthLogs.filter(
    (l) => l.eventType === 'DEEPFAKE_VIRTUAL_CAM_INJECTION'
  );

  const qd2345Assessment = evaluateQd2345Compliance({
    customerType: inferredCustomerType,
    transactionCategory: inferredCategory,
    singleTransactionAmountVnd:
      params.qd2345Context?.singleTransactionAmountVnd ?? latestAlertTx?.amountVnd,
    dailyPriorTransactions:
      params.qd2345Context?.dailyPriorTransactions ?? priorSameDayTxs,
    isFirstTimeOrNewDevice: params.qd2345Context?.isFirstTimeOrNewDevice,
    hasObservedBiometricPass:
      params.qd2345Context?.hasObservedBiometricPass ?? biometricPassLogs.length > 0,
    hasObservedBiometricFailure:
      params.qd2345Context?.hasObservedBiometricFailure ?? biometricFailLogs.length > 0,
    biometricEvidenceIds:
      params.qd2345Context?.biometricEvidenceIds ??
      [...biometricPassLogs, ...biometricFailLogs].map((l) => l.id),
    hasAuthTelemetry:
      params.qd2345Context?.hasAuthTelemetry ?? params.authLogs !== undefined,
  });

  const tt77Assessment = evaluateTt77Compliance({
    devices: params.devices,
    authLogs: primaryAuthLogs,
    flaggedDeviceId,
  });

  const regulatoryReferencesVi: string[] = [
    `Quyết định 2345/QĐ-NHNN (${qd2345Assessment.customerType} • ${qd2345Assessment.transactionCategory}): ${qd2345Assessment.requirementReasonVi} [Ánh xạ yêu cầu: REQUIREMENT_MAPPED • Trạng thái thực thi sinh trắc học: ${qd2345Assessment.biometricVerificationStatus}]`,
    `Thông tư 50/2024/TT-NHNN (sửa đổi, bổ sung bởi Thông tư 77/2025/TT-NHNN, hiệu lực 01/03/2026): Ánh xạ an toàn phiên đăng nhập/API/Webhook, Khoản 4 Điều 8 (sửa bởi Điều 5 TT 77/2025 — trạng thái: ${tt77Assessment.article8Clause4.mappingStatus}, trình duyệt chỉ có tín hiệu mô phỏng) và Điểm c Khoản 5 Điều 11 (sửa bởi Điều 7 TT 77/2025 — PAD ISO 30107 Level 2: ${tt77Assessment.article11Clause5cPad.certificationStatus}).`,
    'Luật Bảo vệ dữ liệu cá nhân số 91/2025/QH15 & Nghị định 356/2025/NĐ-CP (hiệu lực 01/01/2026; thay thế Nghị định 13/2023/NĐ-CP đã hết hiệu lực theo Điều 42 NĐ 356/2025): Bản tin SIMO mô phỏng áp dụng băm xem trước SHA-256 trên client và giả danh hóa có khóa HMAC-SHA-256 trên server (KHÔNG phải ẩn danh hóa tuyệt đối/anonymization hay mã hóa/encryption). Đánh giá đầy đủ nghĩa vụ pháp lý, DPIA & chuyển dữ liệu xuyên biên giới cần LEGAL_REVIEW_REQUIRED.',
  ];

  const geminiDataTransmissionDisclosureVi =
    'Minh bạch Truyền dữ liệu AI (Gemini API — LEGAL_REVIEW_REQUIRED khi triển khai dữ liệu thật): Khi gọi Live Gemini, máy chủ gửi ngữ cảnh điều tra (mã cảnh báo, mã tài khoản/tóm tắt forensics, đoạn hội thoại chưa tin cậy) hoặc ảnh hóa đơn tạm thời (không lưu ảnh gốc vào localStorage/Session Delta). Chính sách sử dụng dữ liệu của Google Gemini API khác nhau giữa Free Tier (có thể dùng cải thiện mô hình ngoài EEA/UK/CH) và Paid Tier (không dùng để huấn luyện); việc truyền dữ liệu cá nhân thật ra máy chủ nước ngoài cần lập hồ sơ đánh giá tác động chuyển dữ liệu xuyên biên giới theo Điều 20 Luật 91/2025/QH15.';

  const dossierId = `DOS-${params.alert.id}`;
  const generatedAt = activeReport.generatedAt || new Date().toISOString();

  const canonicalIntegritySource = JSON.stringify({
    dossierId,
    alertId: params.alert.id,
    classification: activeReport.classification,
    riskScore: params.forensics.deterministicRiskScore,
    primaryAccountId: params.alert.primaryAccountId,
    targetRecipientAccountId: params.alert.targetRecipientAccountId,
    verifiedEvidenceIds: finalEvidenceIds,
    q2345Required: qd2345Assessment.biometricVerificationRequired,
    q2345Status: qd2345Assessment.biometricVerificationStatus,
  });

  const simoPiiMaskedPayload: SimoPiiMaskedReport = {
    schemaVersion: 'SBV-SIMO-v2.5',
    reportingInstitution: 'AEGISOPS_FINTECH_WALLET_NODE',
    complianceStandard: 'QD-2345_TT-50-77_LAW-91-2025_ND-356-2025',
    victimAccountMasked: `${params.alert.primaryAccountId.slice(0, 7)}*** (Pseudonymized Preview)`,
    victimIdentityHashSha256: sha256Hex(params.alert.primaryAccountId),
    piiPseudonymizationMode: 'CLIENT_UNKEYED_SHA256_PREVIEW',
    flaggedMuleAccountNumber: params.alert.targetRecipientAccountId,
    flaggedDeviceId,
    flaggedDeviceFingerprintHash: flaggedDeviceId ? sha256Hex(flaggedDeviceId) : null,
    dossierIntegrityHashSha256: sha256Hex(canonicalIntegritySource),
    riskClassification: activeReport.classification,
    deterministicRiskScore: params.forensics.deterministicRiskScore,
    q2345BiometricThresholdTriggered: qd2345Assessment.biometricVerificationRequired,
    biometricVerificationRequired: qd2345Assessment.biometricVerificationRequired,
    biometricVerificationStatus: qd2345Assessment.biometricVerificationStatus,
    biometricVerificationEvidence: qd2345Assessment.biometricVerificationEvidence,
    tt50DeviceIntegrityViolation:
      activeReport.classification === 'CONFIRMED_ATO_MULE' ||
      activeReport.classification === 'CONFIRMED_LOGIC_ABUSE',
    tt77Article8MappingStatus: tt77Assessment.article8Clause4.mappingStatus,
    tt77PadCertificationStatus: tt77Assessment.article11Clause5cPad.certificationStatus,
  };

  const markdownText = `# BIÊN BẢN ĐIỀU TRA & XỬ LÝ SỰ CỐ AN NINH FINTECH (AEGISOPS)
- **Mã Hồ sơ Tuân thủ:** ${dossierId}
- **Mã Cảnh báo Gốc:** ${params.alert.id} (${params.alert.title})
- **Trạng thái Xử lý:** ${params.alert.status} | **Phân loại:** ${activeReport.classification}
- **Điểm Rủi ro Định lượng:** ${params.forensics.deterministicRiskScore}/100 | **Độ tin cậy AI:** ${activeReport.confidenceScore}%
- **Tài khoản Nguồn:** ${params.alert.primaryAccountId} → **Tài khoản Đích:** ${params.alert.targetRecipientAccountId}
- **Engine Phân tích:** ${activeReport.modelUsed} (${activeReport.latencyMs}ms)

## 1. Tóm tắt Kết luận Điều tra
${activeReport.executiveSummaryVi}

## 2. Đối chiếu Hành lang Pháp lý (QĐ 2345, TT 50/2024 sửa đổi bởi TT 77/2025, Luật 91/2025/QH15 & NĐ 356/2025/NĐ-CP)
${regulatoryReferencesVi.map((r) => `- ${r}`).join('\n')}
- ${geminiDataTransmissionDisclosureVi}

## 3. Danh mục Mã Bằng chứng Đã Kiểm định Tham chiếu (Citation Reference Validation — Chuyên viên rà soát ngữ nghĩa)
${verifiedEvidenceList.map((e) => `- **${e.id}**: ${e.description}`).join('\n')}

## 4. Kết quả 5 Công cụ Kiểm tra Định lượng (Deterministic Forensics)
${params.forensics.toolTraceSteps.map((s) => `- **[${s.status}] ${s.labelVi}**: ${s.summaryVi}`).join('\n')}

## 5. Biện pháp Phản ứng & Lá chắn Bảo vệ Người dùng (SOP Playbook)
${executedActionsVi.map((act) => `- [x] ${act}`).join('\n')}

## 6. Bản tin Đồng bộ SIMO Mô phỏng (SHA-256 Digest / Server HMAC-SHA-256 Pseudonymization — Luật 91/2025/QH15 & NĐ 356/2025/NĐ-CP)
\`\`\`json
${JSON.stringify(simoPiiMaskedPayload, null, 2)}
\`\`\`

## 7. Nhật ký Kiểm toán (Compliance Audit Trail)
${auditTrailSummary.map((log) => `- ${log}`).join('\n')}
`;

  return {
    dossierId,
    alertId: params.alert.id,
    generatedAt,
    severity: params.alert.severity,
    status: params.alert.status,
    classification: activeReport.classification,
    deterministicRiskScore: params.forensics.deterministicRiskScore,
    confidenceScore: activeReport.confidenceScore,
    primaryAccountId: params.alert.primaryAccountId,
    targetRecipientAccountId: params.alert.targetRecipientAccountId,
    modelUsed: activeReport.modelUsed,
    executiveSummaryVi: activeReport.executiveSummaryVi,
    regulatoryReferencesVi,
    geminiDataTransmissionDisclosureVi,
    qd2345Assessment,
    tt77Assessment,
    simoPiiMaskedPayload,
    verifiedEvidenceList,
    forensicStepsSummary: params.forensics.toolTraceSteps.map((s) => ({
      toolName: s.toolName,
      labelVi: s.labelVi,
      status: s.status,
      summaryVi: s.summaryVi,
    })),
    executedActionsVi,
    auditTrailSummary,
    markdownText,
  };
};
