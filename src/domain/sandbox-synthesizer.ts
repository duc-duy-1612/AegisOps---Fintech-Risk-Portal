import { runDeterministicForensicsSuite } from './forensics-analyzers';
import type {
  Account,
  ApiSecurityEvent,
  AuthSessionLog,
  CaseClassification,
  DeviceFingerprint,
  EvidenceArtifact,
  ForensicSuiteOutput,
  FraudAlert,
  StandardCaseInputSpec,
  Transaction,
} from './types';

export interface SandboxExtractedEntities {
  recipientAccountNumber: string;
  recipientOwnerName: string;
  bankOrWalletName: string;
  amountVnd: number;
  scamArchetypeVi: string;
  extractedSignals: string[];
  ocrExtractedTextVi?: string;
}

export interface SynthesizedSandboxBundle {
  alert: FraudAlert;
  senderAccount: Account;
  suspectAccount: Account;
  additionalAccounts: Account[];
  transactions: Transaction[];
  transaction: Transaction;
  device: DeviceFingerprint;
  authLogs: AuthSessionLog[];
  apiEvents: ApiSecurityEvent[];
  evidence: EvidenceArtifact;
  extracted: SandboxExtractedEntities;
  inputSpec: StandardCaseInputSpec;
  computedForensics: ForensicSuiteOutput;
}

export interface CaseBuilderPresetItem {
  id: string;
  badgeVi: string;
  titleVi: string;
  descriptionVi: string;
  expectedRiskLabelVi: string;
  spec: StandardCaseInputSpec;
}

export const CASE_BUILDER_PRESETS: CaseBuilderPresetItem[] = [
  {
    id: 'PRESET-SAFE',
    badgeVi: 'Mẫu 1 • Giao dịch Hợp lệ (An toàn)',
    titleVi: 'Khách hàng chuyển tiền viện phí / học phí tới Đối tác Uy tín',
    descriptionVi:
      'Kiểm chứng cơ chế Trust Dampeners (-38đ): Dù số tiền lớn gấp nhiều lần trung bình, hệ thống nhận diện Đơn vị Uy tín + FaceID chính chủ nên KHÔNG khóa oan.',
    expectedRiskLabelVi: 'Rủi ro dự kiến: ~14/100 (An toàn)',
    spec: {
      customTitle: 'Thanh toán viện phí nội trú khẩn cấp cho Bệnh viện Đa khoa Quốc tế',
      senderName: 'Lê Hoàng Nam',
      senderAccountNumber: '0908555111',
      senderAvgTxVnd: 650_000,
      senderKycLevel: 'LEVEL_2_BIOMETRIC',
      amountVnd: 28_000_000,
      splitTxCount: 1,
      channel: 'VIETQR',
      recipientAccountNumber: '1903888999000',
      recipientOwnerName: 'BENH VIEN CHO RAY (CONG VIEN PHI)',
      bankOrWalletName: 'Vietcombank Doanh Nghiệp (Đã xác thực VietQR Y tế)',
      recipientAccountType: 'TRUSTED_INSTITUTION',
      recipientAccountAgeDays: 2150,
      recipientKycLevel: 'LEVEL_2_BIOMETRIC',
      crossVictimFanInCount: 0,
      deviceIntegrity: 'TRUSTED_PERSONAL_DEVICE',
      sessionSecurity: 'BIOMETRIC_FACEID_PASSED',
      inCallCoercionDetected: false,
      apiConcurrentRequests100ms: 1,
      webhookHmacValid: true,
      rawTranscript:
        'Hóa đơn thanh toán viện phí nội trú mã HS-2026-8891 tại Bệnh viện Chợ Rẫy. Khách hàng quét mã VietQR chính thức tại quầy thu ngân bệnh viện,0 dấu hiệu đe dọa hay thao túng tâm lý.',
    },
  },
  {
    id: 'PRESET-APP-FRAUD',
    badgeVi: 'Mẫu 2 • Lừa đảo Thao túng Tâm lý (APP Fraud)',
    titleVi: 'Giả danh Công an / Shipper ép nạn nhân tự quét FaceID chuyển tiền',
    descriptionVi:
      'Kiểm chứng khả năng bắt lừa đảo lách Quyết định 2345: Chính chủ quét FaceID thật nhưng đang nghe cuộc gọi lạ kéo dài + Dán STK từ Clipboard + Chuyển vào TK Mule nhiều nạn nhân.',
    expectedRiskLabelVi: 'Rủi ro dự kiến: ~95/100 (Chặn khẩn cấp)',
    spec: {
      customTitle: 'Giả danh Cơ quan Công an đe dọa phong tỏa tài sản & ép quét FaceID',
      senderName: 'Nguyễn Thị Thu Hà',
      senderAccountNumber: '0912333444',
      senderAvgTxVnd: 850_000,
      senderKycLevel: 'LEVEL_2_BIOMETRIC',
      amountVnd: 25_000_000,
      splitTxCount: 1,
      channel: 'VIETQR',
      recipientAccountNumber: '1903999888777',
      recipientOwnerName: 'TRAN VAN HUNG',
      bankOrWalletName: 'Techcombank Cá Nhân (TK Mới Mở)',
      recipientAccountType: 'MULE_SUSPECT',
      recipientAccountAgeDays: 4,
      recipientKycLevel: 'LEVEL_1',
      crossVictimFanInCount: 2,
      deviceIntegrity: 'SHARED_EMULATOR_ROOTED',
      sessionSecurity: 'BIOMETRIC_FACEID_PASSED',
      inCallCoercionDetected: true,
      apiConcurrentRequests100ms: 1,
      webhookHmacValid: true,
      rawTranscript:
        'CÁN BỘ ĐIỀU TRA: Tài khoản của chị liên quan đường dây rửa tiền. Yêu cầu chuyển gấp 25.000.000 VNĐ sang STK tạm giữ 1903999888777 (TRAN VAN HUNG) trong 15 phút và giữ bí mật tuyệt đối!',
    },
  },
  {
    id: 'PRESET-CYBER-ATO',
    badgeVi: 'Mẫu 3 • Chiếm đoạt Tài khoản & Chia nhỏ Tiền (ATO)',
    titleVi: 'Phiên sống sót sau đổi mật khẩu (Token Replay) & Chia nhỏ 3 lệnh Smurfing',
    descriptionVi:
      'Kiểm chứng phát hiện xâm nhập An ninh mạng: Session Token cũ không bị thu hồi sau khi đổi mật khẩu trên máy giả lập đã Root + Rút 45 triệu chia làm 3 lệnh 15 triệu.',
    expectedRiskLabelVi: 'Rủi ro dự kiến: ~97/100 (Thu hồi Token & Khóa)',
    spec: {
      customTitle: 'Chiếm đoạt Phiên đăng nhập (Persistent Session Hijack) & Chia nhỏ 45M',
      senderName: 'Trần Quốc Tuấn',
      senderAccountNumber: '0988777666',
      senderAvgTxVnd: 950_000,
      senderKycLevel: 'LEVEL_2_BIOMETRIC',
      amountVnd: 45_000_000,
      splitTxCount: 3,
      channel: 'P2P_WALLET',
      recipientAccountNumber: '1903111222333',
      recipientOwnerName: 'LE VAN TUNG (CUM MULE ATO)',
      bankOrWalletName: 'Ví Điện Tử Liên Kết',
      recipientAccountType: 'MULE_SUSPECT',
      recipientAccountAgeDays: 3,
      recipientKycLevel: 'LEVEL_1',
      crossVictimFanInCount: 1,
      deviceIntegrity: 'SHARED_EMULATOR_ROOTED',
      sessionSecurity: 'SESSION_SURVIVED_PASSWORD_RESET',
      inCallCoercionDetected: false,
      apiConcurrentRequests100ms: 2,
      webhookHmacValid: true,
      rawTranscript:
        'Cảnh báo SOC: Phát hiện Refresh Token Replay trên máy giả lập Android đã root (DEV-EMU-666) ngay sau khi khách hàng vừa đổi mật khẩu. Kẻ tấn công chia nhỏ 45.000.000 ₫ thành 3 lệnh 15.000.000 ₫ liên tiếp.',
    },
  },
  {
    id: 'PRESET-RACE-LOGIC',
    badgeVi: 'Mẫu 4 • Tấn công Lỗ hổng API (Race Condition)',
    titleVi: 'Bắn 12 Request đồng thời trong 100ms (TOCTOU) & Giả mạo Webhook HMAC',
    descriptionVi:
      'Kiểm chứng bảo vệ Backend Fintech: Phát hiện script khai thác xung đột đồng thời để nhân bản tiền hoàn Voucher và gửi callback giả mạo chữ ký HMAC.',
    expectedRiskLabelVi: 'Rủi ro dự kiến: ~93/100 (Khóa Idempotency API)',
    spec: {
      customTitle: 'Khai thác Lỗ hổng Race Condition (12 req/100ms) & Giả mạo Callback HMAC',
      senderName: 'Phạm Gia Huy (Tài khoản Merchant/User)',
      senderAccountNumber: '0933444555',
      senderAvgTxVnd: 1_200_000,
      senderKycLevel: 'LEVEL_1',
      amountVnd: 18_000_000,
      splitTxCount: 1,
      channel: 'VOUCHER_REDEEM',
      recipientAccountNumber: '1903444555666',
      recipientOwnerName: 'PHAM GIA HUY (TK RUT TIEN TRUC LOI)',
      bankOrWalletName: 'Cổng Hoàn Tiền Voucher API',
      recipientAccountType: 'MULE_SUSPECT',
      recipientAccountAgeDays: 9,
      recipientKycLevel: 'LEVEL_1',
      crossVictimFanInCount: 0,
      deviceIntegrity: 'UNRECOGNIZED_FOREIGN_IP',
      sessionSecurity: 'NORMAL_LOGIN',
      inCallCoercionDetected: false,
      apiConcurrentRequests100ms: 12,
      webhookHmacValid: false,
      rawTranscript:
        'Gateway Security Log: Endpoint POST /api/v2/loyalty/voucher-redeem nhận 12 request song song trong 100ms cùng 1 mã khuyến mãi, kèm gói tin Webhook callback có chữ ký X-MoMo-Signature HMAC không hợp lệ.',
    },
  },
];

export const extractEntitiesFromTextDeterministically = (
  rawText: string,
  fallbackAccountNumber?: string,
  fallbackRecipientName?: string,
  fallbackAmountVnd?: number
): SandboxExtractedEntities => {
  const cleanText = rawText.trim();

  const accCodeMatch = cleanText.match(/ACC-[A-Z0-9-]+/i);
  const digitAccMatch = cleanText.match(/\b(\d{8,16})\b/);
  const recipientAccountNumber =
    (fallbackAccountNumber && fallbackAccountNumber.trim()) ||
    (accCodeMatch ? accCodeMatch[0].toUpperCase() : undefined) ||
    (digitAccMatch ? digitAccMatch[1] : undefined) ||
    '1903888999111';

  const nameMatch = cleanText.match(/\b([A-Z]{2,}(?:\s+[A-Z]{2,}){1,4})\b/);
  const recipientOwnerName =
    (fallbackRecipientName && fallbackRecipientName.trim()) ||
    (nameMatch ? nameMatch[1] : undefined) ||
    'NGUYEN VAN B (TK NGHI VAN)';

  let amountVnd = fallbackAmountVnd && fallbackAmountVnd > 0 ? fallbackAmountVnd : 0;
  if (!amountVnd) {
    const millionMatch = cleanText.match(/(\d+(?:[.,]\d+)?)\s*(?:triệu|trieu|tr| củ)\b/i);
    const formattedMatch = cleanText.match(/(\d{1,3}(?:[.,]\d{3}){2,})/);
    const thousandMatch = cleanText.match(/(\d+)\s*k\b/i);
    if (millionMatch && millionMatch[1]) {
      amountVnd = Math.round(parseFloat(millionMatch[1].replace(',', '.')) * 1_000_000);
    } else if (formattedMatch && formattedMatch[1]) {
      amountVnd = parseInt(formattedMatch[1].replace(/[.,]/g, ''), 10);
    } else if (thousandMatch && thousandMatch[1]) {
      amountVnd = parseInt(thousandMatch[1], 10) * 1_000;
    } else {
      amountVnd = 15_000_000;
    }
  }

  const lower = cleanText.toLowerCase();
  const signals: string[] = [];
  let scamArchetypeVi = 'Hồ sơ giao dịch do người dùng khởi tạo kiểm thử';

  if (lower.includes('công an') || lower.includes('điều tra') || lower.includes('tạm giữ')) {
    scamArchetypeVi = 'Giả mạo Cơ quan Công an / Viện kiểm sát đe dọa phong tỏa tài sản';
    signals.push('Giả danh cơ quan chức năng', 'Đe dọa pháp lý khẩn cấp');
  } else if (lower.includes('shipper') || lower.includes('giao hàng') || lower.includes('hoàn tiền')) {
    scamArchetypeVi = 'Giả mạo Shipper / CSKH gửi link hoàn tiền & hủy thẻ hội viên';
    signals.push('Giả danh shipper giao hàng', 'Dụ bấm link hoàn tiền giả mạo');
  } else if (lower.includes('cộng tác viên') || lower.includes('hoa hồng') || lower.includes('nhiệm vụ')) {
    scamArchetypeVi = 'Lừa đảo tuyển Cộng tác viên làm nhiệm vụ hưởng hoa hồng';
    signals.push('Dụ nạp tiền làm nhiệm vụ', 'Cam kết hoàn gốc + lãi cao');
  }

  if (lower.includes('http') || lower.includes('.vn') || lower.includes('.com') || lower.includes('link')) {
    signals.push('Chứa đường dẫn URL nghi vấn Phishing');
  }
  if (lower.includes('gấp') || lower.includes('ngay') || lower.includes('bí mật') || lower.includes('15 phút') || lower.includes('30 phút')) {
    signals.push('Thao túng tâm lý ép buộc thời gian');
  }

  return {
    recipientAccountNumber,
    recipientOwnerName,
    bankOrWalletName: 'Ví Điện Tử / Ngân Hàng Liên Kết',
    amountVnd,
    scamArchetypeVi,
    extractedSignals: signals,
  };
};

export const normalizeCaseInputSpec = (
  params: {
    customTitle?: string;
    rawTranscript?: string;
    imageDataUrl?: string;
    extractedOverrides?: Partial<SandboxExtractedEntities>;
    caseInputSpec?: Partial<StandardCaseInputSpec>;
  }
): StandardCaseInputSpec => {
  const rawTranscript =
    params.caseInputSpec?.rawTranscript ?? params.rawTranscript ?? '';
  const baseExtracted = extractEntitiesFromTextDeterministically(
    rawTranscript,
    params.caseInputSpec?.recipientAccountNumber ?? params.extractedOverrides?.recipientAccountNumber,
    params.caseInputSpec?.recipientOwnerName ?? params.extractedOverrides?.recipientOwnerName,
    params.caseInputSpec?.amountVnd ?? params.extractedOverrides?.amountVnd
  );

  const spec = params.caseInputSpec ?? {};
  const isLikelyTrusted =
    spec.recipientAccountType === 'TRUSTED_INSTITUTION' ||
    baseExtracted.recipientOwnerName.toUpperCase().includes('BENH VIEN') ||
    baseExtracted.recipientOwnerName.toUpperCase().includes('TRUONG');

  return {
    customTitle:
      spec.customTitle?.trim() ||
      params.customTitle?.trim() ||
      baseExtracted.scamArchetypeVi,
    senderName: spec.senderName?.trim() || 'Nguyễn Thị Thu Hà',
    senderAccountNumber: spec.senderAccountNumber?.trim() || '0912333444',
    senderAvgTxVnd:
      typeof spec.senderAvgTxVnd === 'number' && spec.senderAvgTxVnd > 0
        ? spec.senderAvgTxVnd
        : 850_000,
    senderKycLevel: spec.senderKycLevel ?? 'LEVEL_2_BIOMETRIC',
    amountVnd:
      typeof spec.amountVnd === 'number' && spec.amountVnd > 0
        ? spec.amountVnd
        : baseExtracted.amountVnd,
    splitTxCount:
      typeof spec.splitTxCount === 'number' && spec.splitTxCount >= 1
        ? Math.min(5, Math.round(spec.splitTxCount))
        : 1,
    channel: spec.channel ?? 'VIETQR',
    recipientAccountNumber:
      spec.recipientAccountNumber?.trim() || baseExtracted.recipientAccountNumber,
    recipientOwnerName:
      spec.recipientOwnerName?.trim() || baseExtracted.recipientOwnerName,
    bankOrWalletName:
      spec.bankOrWalletName?.trim() ||
      (isLikelyTrusted
        ? 'Ngân hàng Đối tác Doanh nghiệp (Đã xác thực)'
        : baseExtracted.bankOrWalletName),
    recipientAccountType:
      spec.recipientAccountType ?? (isLikelyTrusted ? 'TRUSTED_INSTITUTION' : 'MULE_SUSPECT'),
    recipientAccountAgeDays:
      typeof spec.recipientAccountAgeDays === 'number' && spec.recipientAccountAgeDays >= 1
        ? spec.recipientAccountAgeDays
        : isLikelyTrusted
          ? 1800
          : 4,
    recipientKycLevel:
      spec.recipientKycLevel ?? (isLikelyTrusted ? 'LEVEL_2_BIOMETRIC' : 'LEVEL_1'),
    crossVictimFanInCount:
      typeof spec.crossVictimFanInCount === 'number' && spec.crossVictimFanInCount >= 0
        ? Math.min(4, Math.round(spec.crossVictimFanInCount))
        : isLikelyTrusted
          ? 0
          : 1,
    deviceIntegrity:
      spec.deviceIntegrity ??
      (isLikelyTrusted ? 'TRUSTED_PERSONAL_DEVICE' : 'SHARED_EMULATOR_ROOTED'),
    sessionSecurity: spec.sessionSecurity ?? 'BIOMETRIC_FACEID_PASSED',
    inCallCoercionDetected:
      typeof spec.inCallCoercionDetected === 'boolean'
        ? spec.inCallCoercionDetected
        : !isLikelyTrusted && baseExtracted.extractedSignals.length > 0,
    deepfakeOrVirtualCamDetected:
      typeof spec.deepfakeOrVirtualCamDetected === 'boolean'
        ? spec.deepfakeOrVirtualCamDetected
        : false,
    apiConcurrentRequests100ms:
      typeof spec.apiConcurrentRequests100ms === 'number' && spec.apiConcurrentRequests100ms >= 1
        ? Math.min(50, Math.round(spec.apiConcurrentRequests100ms))
        : 1,
    webhookHmacValid:
      typeof spec.webhookHmacValid === 'boolean' ? spec.webhookHmacValid : true,
    rawTranscript,
    imageDataUrl: spec.imageDataUrl ?? params.imageDataUrl,
  };
};

export const synthesizeSandboxCase = (params: {
  customTitle?: string;
  rawTranscript: string;
  imageDataUrl?: string;
  extractedOverrides?: Partial<SandboxExtractedEntities>;
  caseInputSpec?: Partial<StandardCaseInputSpec>;
  existingAccounts: Account[];
  batchIndex?: number;
}): SynthesizedSandboxBundle => {
  const uniqueSeed =
    typeof params.batchIndex === 'number'
      ? `${Date.now().toString().slice(-4)}B${params.batchIndex + 1}`
      : Date.now().toString().slice(-4);
  const suffix = uniqueSeed;
  const alertId = `ALT-SND-${suffix}`;

  const inputSpec = normalizeCaseInputSpec(params);
  const baseExtracted = extractEntitiesFromTextDeterministically(
    inputSpec.rawTranscript,
    inputSpec.recipientAccountNumber,
    inputSpec.recipientOwnerName,
    inputSpec.amountVnd
  );

  const dynamicSignals = [...baseExtracted.extractedSignals];
  if (inputSpec.inCallCoercionDetected) {
    dynamicSignals.push(
      'In-Call Telemetry: Khách đang nghe cuộc gọi lạ kéo dài >15 phút + Dán STK từ Clipboard khi quét FaceID (Lách QĐ 2345)'
    );
  }
  if (inputSpec.sessionSecurity === 'SESSION_SURVIVED_PASSWORD_RESET') {
    dynamicSignals.push('Phát hiện Session Token sống sót bất thường sau khi đổi mật khẩu (ATO)');
  }
  if (inputSpec.deepfakeOrVirtualCamDetected) {
    dynamicSignals.push(
      'Cảnh báo Deepfake / Virtual Camera Injection (Vi phạm ISO/IEC 30107-3 Liveness PAD)'
    );
  }
  if (inputSpec.apiConcurrentRequests100ms >= 5 || !inputSpec.webhookHmacValid) {
    dynamicSignals.push(
      `Dấu hiệu khai thác API: ${inputSpec.apiConcurrentRequests100ms} req/100ms • HMAC: ${inputSpec.webhookHmacValid ? 'Hợp lệ' : 'Giả mạo'}`
    );
  }
  if (inputSpec.recipientAccountType === 'TRUSTED_INSTITUTION' && dynamicSignals.length === 0) {
    dynamicSignals.push('Đối tác thụ hưởng uy tín đã xác thực • 0 dấu hiệu thao túng tâm lý');
  }

  const extracted: SandboxExtractedEntities = {
    recipientAccountNumber: inputSpec.recipientAccountNumber,
    recipientOwnerName: inputSpec.recipientOwnerName,
    bankOrWalletName: inputSpec.bankOrWalletName,
    amountVnd: inputSpec.amountVnd,
    scamArchetypeVi: inputSpec.customTitle || baseExtracted.scamArchetypeVi,
    extractedSignals:
      params.extractedOverrides?.extractedSignals && params.extractedOverrides.extractedSignals.length > 0
        ? Array.from(new Set([...params.extractedOverrides.extractedSignals, ...dynamicSignals]))
        : Array.from(new Set(dynamicSignals)),
    ocrExtractedTextVi: params.extractedOverrides?.ocrExtractedTextVi,
  };

  // 1. Synthesize Sender Account from Part 1 Inputs
  const senderAccountId = `ACC-USR-${suffix}`;
  const senderDeviceId =
    inputSpec.deviceIntegrity === 'SHARED_EMULATOR_ROOTED'
      ? 'DEV-EMU-666'
      : `DEV-USR-${suffix}`;

  const senderAccount: Account = {
    id: senderAccountId,
    ownerName: inputSpec.senderName,
    accountNumber: inputSpec.senderAccountNumber,
    bankOrWalletName: 'Ví MoMo Cá Nhân',
    accountType: 'CONSUMER',
    status: 'ACTIVE',
    balanceVnd: Math.max(50_000_000, inputSpec.amountVnd * 2),
    avgTxAmountVnd: inputSpec.senderAvgTxVnd,
    kycLevel: inputSpec.senderKycLevel,
    primaryDeviceId: senderDeviceId,
    accountAgeDays: 920,
  };

  // 2. Synthesize Recipient Account from Part 2 Inputs
  const matchedAccount = params.existingAccounts.find(
    (a) =>
      a.id === inputSpec.recipientAccountNumber ||
      a.accountNumber === inputSpec.recipientAccountNumber
  );

  const suspectAccountId = matchedAccount
    ? matchedAccount.id
    : inputSpec.recipientAccountNumber.startsWith('ACC-')
      ? inputSpec.recipientAccountNumber
      : `ACC-SND-${inputSpec.recipientAccountNumber.slice(-4)}-${suffix.slice(-2)}`;

  const recipientDeviceId =
    inputSpec.deviceIntegrity === 'SHARED_EMULATOR_ROOTED'
      ? 'DEV-EMU-666'
      : `DEV-RCV-${suffix}`;

  const suspectAccount: Account = {
    id: suspectAccountId,
    ownerName: inputSpec.recipientOwnerName,
    accountNumber: inputSpec.recipientAccountNumber,
    bankOrWalletName: inputSpec.bankOrWalletName,
    accountType: inputSpec.recipientAccountType,
    status: 'ACTIVE',
    balanceVnd: inputSpec.amountVnd * 2,
    avgTxAmountVnd: 1_500_000,
    kycLevel: inputSpec.recipientKycLevel,
    primaryDeviceId: recipientDeviceId,
    accountAgeDays: inputSpec.recipientAccountAgeDays,
  };

  // 3. Synthesize Device Fingerprint from Part 3 Inputs
  const isEmulator = inputSpec.deviceIntegrity === 'SHARED_EMULATOR_ROOTED';
  const device: DeviceFingerprint = {
    id: recipientDeviceId,
    osBrowser: isEmulator
      ? 'Android 11 (Rooted NoxPlayer Emulator • Magisk Hide)'
      : inputSpec.deviceIntegrity === 'UNRECOGNIZED_FOREIGN_IP'
        ? 'Linux Headless Bot / Proxy ASN-9009'
        : 'iOS 18.1 • MoMo Official App (Secure Enclave)',
    ipAddress:
      inputSpec.deviceIntegrity === 'UNRECOGNIZED_FOREIGN_IP'
        ? '185.220.101.44'
        : isEmulator
          ? '103.199.16.88'
          : '14.161.22.108',
    asnLocation:
      inputSpec.deviceIntegrity === 'UNRECOGNIZED_FOREIGN_IP'
        ? 'Foreign Anonymous VPN Node'
        : isEmulator
          ? 'Poipet Border DataCenter Proxy'
          : 'TP. Hồ Chí Minh, Việt Nam',
    isEmulatorOrRooted: isEmulator,
    linkedAccountIds: isEmulator
      ? Array.from(new Set([suspectAccount.id, 'ACC-MULE-901', 'ACC-MULE-902', 'ACC-MULE-903']))
      : [suspectAccount.id],
  };

  // 4. Synthesize Transactions (supports Smurfing splitTxCount & Cross-Victim Fan-In)
  const transactions: Transaction[] = [];
  const perTxAmount = Math.round(inputSpec.amountVnd / Math.max(1, inputSpec.splitTxCount));
  for (let i = 0; i < inputSpec.splitTxCount; i += 1) {
    transactions.push({
      id: `TXN-SND-${suffix}-${i + 1}`,
      alertId,
      senderAccountId: senderAccount.id,
      receiverAccountId: suspectAccount.id,
      amountVnd:
        i === inputSpec.splitTxCount - 1
          ? inputSpec.amountVnd - perTxAmount * (inputSpec.splitTxCount - 1)
          : perTxAmount,
      channel: inputSpec.channel,
      message:
        inputSpec.splitTxCount > 1
          ? `Lenh chia nho #${i + 1}/${inputSpec.splitTxCount} (${inputSpec.recipientAccountNumber})`
          : `Chuyen khoan tới ${inputSpec.recipientAccountNumber}`,
      deviceId: senderDeviceId,
      hopIndex: i + 1,
      status: 'HELD',
      timestamp: new Date(Date.now() - (inputSpec.splitTxCount - i) * 25_000).toISOString(),
    });
  }

  // Synthesize Cross-Victim Fan-In accounts & transactions if crossVictimFanInCount > 0
  const additionalAccounts: Account[] = [];
  const fanInNames = [
    'Phạm Minh Đức (Nạn nhân liên đới #2)',
    'Hoàng Thị Lan (Nạn nhân liên đới #3)',
    'Vũ Đình Trọng (Nạn nhân liên đới #4)',
    'Đặng Thu Thảo (Nạn nhân liên đới #5)',
  ];
  for (let v = 0; v < inputSpec.crossVictimFanInCount; v += 1) {
    const fanVictimId = `ACC-FAN-${suffix}-${v + 1}`;
    additionalAccounts.push({
      id: fanVictimId,
      ownerName: fanInNames[v] ?? `Khách hàng Liên đới #${v + 2}`,
      accountNumber: `097700010${v + 1}`,
      bankOrWalletName: 'Ví MoMo Cá Nhân',
      accountType: 'CONSUMER',
      status: 'ACTIVE',
      balanceVnd: 15_000_000,
      avgTxAmountVnd: 700_000,
      kycLevel: 'LEVEL_2_BIOMETRIC',
      primaryDeviceId: `DEV-FAN-${v + 1}`,
      accountAgeDays: 640,
    });
    transactions.push({
      id: `TXN-FAN-${suffix}-${v + 1}`,
      alertId,
      senderAccountId: fanVictimId,
      receiverAccountId: suspectAccount.id,
      amountVnd: Math.max(5_000_000, Math.round(inputSpec.amountVnd * 0.65)),
      channel: inputSpec.channel,
      message: `Chuyen tien vao cung TK nhan ${inputSpec.recipientAccountNumber}`,
      deviceId: `DEV-FAN-${v + 1}`,
      hopIndex: 1,
      status: 'COMPLETED',
      timestamp: new Date(Date.now() - (v + 2) * 180_000).toISOString(),
    });
  }

  // 5. Synthesize AuthSessionLogs from Part 3 Inputs
  const authLogs: AuthSessionLog[] = [];
  if (inputSpec.deepfakeOrVirtualCamDetected) {
    authLogs.push({
      id: `LOG-DFK-${suffix}`,
      accountId: senderAccount.id,
      deviceId: device.id,
      eventType: 'DEEPFAKE_VIRTUAL_CAM_INJECTION',
      sessionFamilyId: `FAM-DFK-${suffix}`,
      survivedCredentialReset: false,
      ipAddress: device.ipAddress,
      location: device.asnLocation,
      timestamp: new Date(Date.now() - 40_000).toISOString(),
      summary:
        'CẢNH BÁO DEEPFAKE (ISO 30107-3 Liveness PAD): Phát hiện hook Camera ảo chèn luồng video Deepfake đánh lừa xác thực FaceID QĐ 2345.',
    });
  }
  if (inputSpec.sessionSecurity === 'SESSION_SURVIVED_PASSWORD_RESET') {
    authLogs.push(
      {
        id: `LOG-ATO-${suffix}-1`,
        accountId: senderAccount.id,
        deviceId: device.id,
        eventType: 'SESSION_SURVIVED_RESET',
        sessionFamilyId: `FAM-ATO-${suffix}`,
        survivedCredentialReset: true,
        ipAddress: device.ipAddress,
        location: device.asnLocation,
        timestamp: new Date(Date.now() - 120_000).toISOString(),
        summary: `CẢNH BÁO ATO: Phiên FAM-ATO-${suffix} tồn tại bất thường sau khi khách đổi mật khẩu trên ${device.osBrowser}.`,
      },
      {
        id: `LOG-ATO-${suffix}-2`,
        accountId: senderAccount.id,
        deviceId: device.id,
        eventType: 'REFRESH_TOKEN_REPLAY',
        sessionFamilyId: `FAM-ATO-${suffix}`,
        survivedCredentialReset: true,
        ipAddress: device.ipAddress,
        location: device.asnLocation,
        timestamp: new Date(Date.now() - 60_000).toISOString(),
        summary: `Phát hiện Refresh Token Replay từ IP ${device.ipAddress} (${device.asnLocation}).`,
      }
    );
  } else if (inputSpec.sessionSecurity === 'BIOMETRIC_FACEID_PASSED') {
    authLogs.push({
      id: `LOG-BIO-${suffix}`,
      accountId: senderAccount.id,
      deviceId: senderDeviceId,
      eventType: 'BIOMETRIC_STEP_UP_PASS',
      sessionFamilyId: `FAM-BIO-${suffix}`,
      survivedCredentialReset: false,
      ipAddress: '14.161.22.108',
      location: 'TP. Hồ Chí Minh, Việt Nam',
      timestamp: new Date(Date.now() - 45_000).toISOString(),
      summary: inputSpec.inCallCoercionDetected
        ? 'Chính chủ vượt qua FaceID QĐ 2345 (Liveness 99.4%) NHƯNG Telemetry ghi nhận: Đang mở cuộc gọi thoại 18 phút + Dán STK người nhận từ Clipboard.'
        : 'Chính chủ xác thực sinh trắc học FaceID + NFC CCCD hợp lệ trên thiết bị tin cậy (0 cuộc gọi lạ).',
    });
  } else {
    authLogs.push({
      id: `LOG-LGN-${suffix}`,
      accountId: senderAccount.id,
      deviceId: senderDeviceId,
      eventType: 'LOGIN_SUCCESS',
      sessionFamilyId: `FAM-LGN-${suffix}`,
      survivedCredentialReset: false,
      ipAddress: device.ipAddress,
      location: device.asnLocation,
      timestamp: new Date(Date.now() - 90_000).toISOString(),
      summary: `Đăng nhập phiên tiêu chuẩn trên thiết bị ${senderDeviceId}.`,
    });
  }

  // 6. Synthesize ApiSecurityEvents from Part 3 Inputs
  const apiEvents: ApiSecurityEvent[] = [];
  if (inputSpec.apiConcurrentRequests100ms >= 5 || !inputSpec.webhookHmacValid) {
    apiEvents.push({
      id: `EVT-API-${suffix}`,
      alertId,
      accountId: senderAccount.id,
      endpoint: 'POST /api/v2/wallet/transfer-or-redeem',
      concurrentRequests100ms: inputSpec.apiConcurrentRequests100ms,
      hmacSignatureValid: inputSpec.webhookHmacValid,
      anomalyClass:
        inputSpec.apiConcurrentRequests100ms >= 5 ? 'RACE_CONDITION_TOCTOU' : 'WEBHOOK_SPOOF',
      payloadSummary: `Ghi nhận ${inputSpec.apiConcurrentRequests100ms} request đồng thời trong 100ms • Chữ ký HMAC: ${
        inputSpec.webhookHmacValid ? 'Hợp lệ' : 'SAI CHỮ KÝ (INVALID_HMAC)'
      }.`,
      timestamp: new Date().toISOString(),
    });
  }

  // 7. Synthesize Multimodal Evidence Artifact from Part 4 Inputs
  const evidence: EvidenceArtifact = {
    id: `EVD-SND-${suffix}`,
    alertId,
    kind: inputSpec.imageDataUrl
      ? 'SCREENSHOT_IMAGE'
      : inputSpec.recipientAccountType === 'TRUSTED_INSTITUTION'
        ? 'MEDICAL_INVOICE'
        : 'CHAT_TRANSCRIPT',
    title: inputSpec.imageDataUrl
      ? 'Ảnh chụp màn hình bằng chứng tải lên (Gemini Multimodal Vision OCR)'
      : 'Hồ sơ Bằng chứng & Ngữ cảnh Giao dịch Đầu vào',
    textContent:
      extracted.ocrExtractedTextVi && !inputSpec.rawTranscript.trim()
        ? `[Gemini Vision OCR Trích xuất Trực tiếp từ Ảnh]: "${extracted.ocrExtractedTextVi}" — Giao dịch ${inputSpec.amountVnd.toLocaleString('vi-VN')} ₫ tới STK ${inputSpec.recipientAccountNumber} (${inputSpec.recipientOwnerName}).`
        : inputSpec.rawTranscript.trim() ||
          `Hồ sơ kiểm thử: ${inputSpec.senderName} chuyển ${inputSpec.amountVnd.toLocaleString('vi-VN')} ₫ (${inputSpec.splitTxCount} lệnh) tới STK ${inputSpec.recipientAccountNumber} (${inputSpec.recipientOwnerName}).`,
    imageDataUrl: inputSpec.imageDataUrl,
    extractedSignals: extracted.extractedSignals,
  };

  // Determine dynamic ScenarioCode based on real inputs
  const dynamicScenarioCode: FraudAlert['scenarioCode'] =
    inputSpec.recipientAccountType === 'TRUSTED_INSTITUTION' &&
    inputSpec.sessionSecurity !== 'SESSION_SURVIVED_PASSWORD_RESET' &&
    inputSpec.apiConcurrentRequests100ms < 5 &&
    inputSpec.webhookHmacValid &&
    !inputSpec.inCallCoercionDetected
      ? 'SMART_FALSE_POSITIVE'
      : 'CUSTOM_SANDBOX';

  const draftAlert: FraudAlert = {
    id: alertId,
    title: inputSpec.customTitle || `[Hồ sơ Kiểm thử] ${extracted.scamArchetypeVi}`,
    subtitle: `${inputSpec.senderName} → STK ${inputSpec.recipientAccountNumber} (${inputSpec.recipientOwnerName}) • ${inputSpec.amountVnd.toLocaleString('vi-VN')} ₫ (${inputSpec.splitTxCount} lệnh)`,
    scenarioCode: dynamicScenarioCode,
    primaryAccountId: senderAccount.id,
    targetRecipientAccountId: suspectAccount.id,
    severity: 'HIGH',
    status: 'OPEN',
    deterministicRiskScore: 50,
    tracks: ['AI_ASSISTANT', 'ANTI_SCAM', 'CYBERSECURITY'],
    createdAt: new Date().toISOString(),
    traditionalRuleReason:
      'Hồ sơ giao dịch được khởi tạo từ Biểu mẫu Kiểm thử Chuẩn hóa 4 Phần (Standardized Case Builder).',
  };

  // 8. Run the real deterministic forensics suite on the synthesized records to compute the TRUE risk score!
  const allAccountsForEval = [
    senderAccount,
    suspectAccount,
    ...additionalAccounts,
    ...params.existingAccounts.filter(
      (a) => a.id !== senderAccount.id && a.id !== suspectAccount.id
    ),
  ];

  const computedForensics = runDeterministicForensicsSuite({
    alert: draftAlert,
    accounts: allAccountsForEval,
    devices: [device],
    authLogs,
    transactions,
    apiEvents,
    evidences: [evidence],
  });

  const finalRiskScore = computedForensics.deterministicRiskScore;
  const finalSeverity: FraudAlert['severity'] =
    finalRiskScore >= 80
      ? 'CRITICAL'
      : finalRiskScore >= 55
        ? 'HIGH'
        : finalRiskScore >= 30
          ? 'MEDIUM'
          : 'LOW';

  const alert: FraudAlert = {
    ...draftAlert,
    deterministicRiskScore: finalRiskScore,
    severity: finalSeverity,
  };

  return {
    alert,
    senderAccount,
    suspectAccount,
    additionalAccounts,
    transactions,
    transaction: transactions[0]!,
    device,
    authLogs,
    apiEvents,
    evidence,
    extracted,
    inputSpec,
    computedForensics: {
      ...computedForensics,
      alertId: alert.id,
    },
  };
};

/**
 * Pure real-time preview calculator for the 4-Part Case Builder Form.
 * Runs in <2ms on every keystroke so the user sees the real deterministic score, Z-Score,
 * Smurfing Entropy, and classification change live as they edit form parameters.
 */
export const evaluateLiveCaseInputPreview = (
  partialSpec: Partial<StandardCaseInputSpec>,
  existingAccounts: Account[] = []
): {
  riskScore: number;
  classification: CaseClassification;
  zScoreDeviation: number;
  smurfingEntropyIndex: number;
  deviceBipartiteClusterScore: number;
  crossVictimFanIn: number;
  factors: ForensicSuiteOutput['riskAttributionFactors'];
} => {
  const bundle = synthesizeSandboxCase({
    customTitle: partialSpec.customTitle,
    rawTranscript: partialSpec.rawTranscript ?? '',
    imageDataUrl: partialSpec.imageDataUrl,
    caseInputSpec: partialSpec,
    existingAccounts,
  });

  return {
    riskScore: bundle.computedForensics.deterministicRiskScore,
    classification: bundle.computedForensics.fallbackReport.classification,
    zScoreDeviation: bundle.computedForensics.quantitativeMetrics.zScoreDeviation,
    smurfingEntropyIndex: bundle.computedForensics.quantitativeMetrics.smurfingEntropyIndex,
    deviceBipartiteClusterScore:
      bundle.computedForensics.quantitativeMetrics.deviceBipartiteClusterScore,
    crossVictimFanIn: bundle.computedForensics.quantitativeMetrics.crossVictimFanIn,
    factors: bundle.computedForensics.riskAttributionFactors,
  };
};

/**
 * Extracts a standardized 4-Part StandardCaseInputSpec from any existing alert in the workspace
 * so the user can view or edit any case's parameters in the same unified format.
 */
export const deriveCaseInputSpecFromAlert = (params: {
  alert: FraudAlert;
  accounts: Account[];
  devices: DeviceFingerprint[];
  authLogs: AuthSessionLog[];
  transactions: Transaction[];
  apiEvents: ApiSecurityEvent[];
  evidences: EvidenceArtifact[];
  storedSpec?: StandardCaseInputSpec;
}): StandardCaseInputSpec => {
  if (params.storedSpec) {
    return params.storedSpec;
  }

  const sender = params.accounts.find((a) => a.id === params.alert.primaryAccountId);
  const recipient = params.accounts.find((a) => a.id === params.alert.targetRecipientAccountId);
  const alertTxs = params.transactions.filter((t) => t.alertId === params.alert.id);
  const senderTxs = alertTxs.filter((t) => t.senderAccountId === params.alert.primaryAccountId);
  const totalAmount =
    (senderTxs.length > 0 ? senderTxs : alertTxs).reduce((s, t) => s + t.amountVnd, 0) ||
    15_000_000;
  const distinctSenders = new Set(alertTxs.map((t) => t.senderAccountId));
  const crossVictimFanInCount = Math.max(0, distinctSenders.size - 1);

  const recDev = params.devices.find((d) => d.id === recipient?.primaryDeviceId);
  const senderLogs = params.authLogs.filter((l) => l.accountId === params.alert.primaryAccountId);
  const hasSurvivedReset = senderLogs.some((l) => l.survivedCredentialReset);
  const hasBiometricPass = senderLogs.some((l) => l.eventType === 'BIOMETRIC_STEP_UP_PASS');
  const hasDeepfake = senderLogs.some((l) => l.eventType === 'DEEPFAKE_VIRTUAL_CAM_INJECTION');

  const alertEvidences = params.evidences.filter((e) => e.alertId === params.alert.id);
  const firstEv = alertEvidences[0];
  const hasInCallSignal = alertEvidences.some(
    (e) =>
      e.textContent.toLowerCase().includes('cuộc gọi') ||
      e.extractedSignals.some((s) => s.toLowerCase().includes('in-call') || s.toLowerCase().includes('cuộc gọi'))
  );

  const alertApis = params.apiEvents.filter((e) => e.alertId === params.alert.id);
  const maxConcurrent = alertApis.reduce(
    (max, e) => Math.max(max, e.concurrentRequests100ms),
    1
  );
  const hmacValid = alertApis.every((e) => e.hmacSignatureValid);

  return {
    customTitle: params.alert.title,
    senderName: sender?.ownerName ?? 'Khách hàng Ví MoMo',
    senderAccountNumber: sender?.accountNumber ?? '0909123456',
    senderAvgTxVnd: sender?.avgTxAmountVnd ?? 850_000,
    senderKycLevel: sender?.kycLevel ?? 'LEVEL_2_BIOMETRIC',
    amountVnd: totalAmount,
    splitTxCount: Math.max(1, senderTxs.length),
    channel: alertTxs[0]?.channel ?? 'VIETQR',
    recipientAccountNumber: recipient?.accountNumber ?? params.alert.targetRecipientAccountId,
    recipientOwnerName: recipient?.ownerName ?? 'TÀI KHOẢN THỤ HƯỞNG',
    bankOrWalletName: recipient?.bankOrWalletName ?? 'Ngân hàng / Ví Liên kết',
    recipientAccountType: recipient?.accountType ?? 'MULE_SUSPECT',
    recipientAccountAgeDays: recipient?.accountAgeDays ?? 5,
    recipientKycLevel: recipient?.kycLevel ?? 'LEVEL_1',
    crossVictimFanInCount,
    deviceIntegrity: recDev?.isEmulatorOrRooted
      ? 'SHARED_EMULATOR_ROOTED'
      : 'TRUSTED_PERSONAL_DEVICE',
    sessionSecurity: hasSurvivedReset
      ? 'SESSION_SURVIVED_PASSWORD_RESET'
      : hasBiometricPass
        ? 'BIOMETRIC_FACEID_PASSED'
        : 'NORMAL_LOGIN',
    inCallCoercionDetected: hasInCallSignal,
    deepfakeOrVirtualCamDetected: hasDeepfake,
    apiConcurrentRequests100ms: maxConcurrent,
    webhookHmacValid: hmacValid,
    rawTranscript: firstEv?.textContent ?? params.alert.subtitle,
    imageDataUrl: firstEv?.imageDataUrl,
  };
};
