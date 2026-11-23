import type {
  Account,
  ForensicSuiteOutput,
  FraudAlert,
  StandardCaseInputSpec,
} from './types';

const parseCsvLines = (raw: string): string[][] => {
  const rows: string[][] = [];
  let currentRow: string[] = [];
  let currentCell = '';
  let inQuotes = false;
  const clean = raw.replace(/^\uFEFF/, '').replace(/\r\n/g, '\n').replace(/\r/g, '\n');

  for (let i = 0; i < clean.length; i += 1) {
    const ch = clean[i]!;
    if (ch === '"') {
      if (inQuotes && clean[i + 1] === '"') {
        currentCell += '"';
        i += 1;
      } else {
        inQuotes = !inQuotes;
      }
    } else if (ch === ',' && !inQuotes) {
      currentRow.push(currentCell.trim());
      currentCell = '';
    } else if (ch === '\n' && !inQuotes) {
      currentRow.push(currentCell.trim());
      if (currentRow.some((c) => c.length > 0)) {
        rows.push(currentRow);
      }
      currentRow = [];
      currentCell = '';
    } else {
      currentCell += ch;
    }
  }

  if (currentCell.length > 0 || currentRow.length > 0) {
    currentRow.push(currentCell.trim());
    if (currentRow.some((c) => c.length > 0)) {
      rows.push(currentRow);
    }
  }

  return rows;
};

const toPositiveInt = (val: unknown, fallback: number): number => {
  if (typeof val === 'number' && Number.isFinite(val) && val > 0) return Math.round(val);
  if (typeof val === 'string') {
    const cleaned = Number(val.replace(/[^\d.-]/g, ''));
    if (Number.isFinite(cleaned) && cleaned > 0) return Math.round(cleaned);
  }
  return fallback;
};

const toBooleanFlag = (val: unknown, fallback: boolean): boolean => {
  if (typeof val === 'boolean') return val;
  if (typeof val === 'string') {
    const lower = val.trim().toLowerCase();
    if (['true', '1', 'yes', 'co', 'có'].includes(lower)) return true;
    if (['false', '0', 'no', 'khong', 'không'].includes(lower)) return false;
  }
  return fallback;
};

const normalizeRecordToSpec = (
  rec: Record<string, unknown>
): Partial<StandardCaseInputSpec> => {
  const recTypeRaw = String(rec.recipientAccountType ?? '').toUpperCase();
  const recipientAccountType: StandardCaseInputSpec['recipientAccountType'] =
    recTypeRaw === 'TRUSTED_INSTITUTION' || recTypeRaw === 'CONSUMER' || recTypeRaw === 'MERCHANT'
      ? (recTypeRaw as StandardCaseInputSpec['recipientAccountType'])
      : 'MULE_SUSPECT';

  const channelRaw = String(rec.channel ?? '').toUpperCase();
  const channel: StandardCaseInputSpec['channel'] =
    channelRaw === 'P2P_WALLET' ||
    channelRaw === 'VIETQR' ||
    channelRaw === 'PAYMENT_GATEWAY' ||
    channelRaw === 'VOUCHER_REDEEM'
      ? (channelRaw as StandardCaseInputSpec['channel'])
      : 'VIETQR';

  const devRaw = String(rec.deviceIntegrity ?? '').toUpperCase();
  const deviceIntegrity: StandardCaseInputSpec['deviceIntegrity'] =
    devRaw === 'TRUSTED_PERSONAL_DEVICE' ||
    devRaw === 'SHARED_EMULATOR_ROOTED' ||
    devRaw === 'UNRECOGNIZED_FOREIGN_IP'
      ? (devRaw as StandardCaseInputSpec['deviceIntegrity'])
      : recipientAccountType === 'TRUSTED_INSTITUTION'
        ? 'TRUSTED_PERSONAL_DEVICE'
        : 'SHARED_EMULATOR_ROOTED';

  const sessRaw = String(rec.sessionSecurity ?? '').toUpperCase();
  const sessionSecurity: StandardCaseInputSpec['sessionSecurity'] =
    sessRaw === 'BIOMETRIC_FACEID_PASSED' ||
    sessRaw === 'SESSION_SURVIVED_PASSWORD_RESET' ||
    sessRaw === 'NORMAL_LOGIN'
      ? (sessRaw as StandardCaseInputSpec['sessionSecurity'])
      : 'BIOMETRIC_FACEID_PASSED';

  return {
    customTitle: String(rec.customTitle ?? rec.title ?? '').trim() || undefined,
    senderName: String(rec.senderName ?? 'Khách hàng Batch Import').trim(),
    senderAccountNumber: String(rec.senderAccountNumber ?? '0909888111').trim(),
    senderAvgTxVnd: toPositiveInt(rec.senderAvgTxVnd, 850_000),
    amountVnd: toPositiveInt(rec.amountVnd, 15_000_000),
    splitTxCount: Math.min(5, toPositiveInt(rec.splitTxCount, 1)),
    channel,
    recipientAccountNumber: String(
      rec.recipientAccountNumber ?? rec.recipientAccount ?? '1903777888999'
    ).trim(),
    recipientOwnerName: String(
      rec.recipientOwnerName ?? rec.recipientName ?? 'TAI KHOAN THU HUONG'
    ).trim(),
    recipientAccountType,
    recipientAccountAgeDays: toPositiveInt(
      rec.recipientAccountAgeDays,
      recipientAccountType === 'TRUSTED_INSTITUTION' ? 1800 : 5
    ),
    crossVictimFanInCount: Math.min(
      4,
      Math.max(0, Number(rec.crossVictimFanInCount ?? 0) || 0)
    ),
    deviceIntegrity,
    sessionSecurity,
    inCallCoercionDetected: toBooleanFlag(rec.inCallCoercionDetected, false),
    deepfakeOrVirtualCamDetected: toBooleanFlag(rec.deepfakeOrVirtualCamDetected, false),
    apiConcurrentRequests100ms: toPositiveInt(rec.apiConcurrentRequests100ms, 1),
    webhookHmacValid: toBooleanFlag(rec.webhookHmacValid, true),
    rawTranscript: String(rec.rawTranscript ?? rec.message ?? '').trim(),
  };
};

export const parseBatchCasesPayload = (
  rawContent: string,
  fileName = 'batch.csv'
): { specs: Partial<StandardCaseInputSpec>[]; warnings: string[] } => {
  const trimmed = rawContent.replace(/^\uFEFF/, '').trim();
  if (!trimmed) {
    return { specs: [], warnings: ['Tệp dữ liệu trống.'] };
  }

  const warnings: string[] = [];
  const isJson = fileName.toLowerCase().endsWith('.json') || trimmed.startsWith('[') || trimmed.startsWith('{');

  if (isJson) {
    const parsed = JSON.parse(trimmed) as unknown;
    const arr = Array.isArray(parsed)
      ? parsed
      : typeof parsed === 'object' && parsed !== null && Array.isArray((parsed as { cases?: unknown[] }).cases)
        ? (parsed as { cases: unknown[] }).cases
        : [parsed];

    const specs = arr
      .filter((item): item is Record<string, unknown> => typeof item === 'object' && item !== null)
      .slice(0, 15)
      .map(normalizeRecordToSpec);

    if (arr.length > 15) {
      warnings.push('Hệ thống chỉ nhập tối đa 15 hồ sơ/lần để đảm bảo hiệu năng.');
    }
    return { specs, warnings };
  }

  const rows = parseCsvLines(trimmed);
  if (rows.length < 2) {
    return {
      specs: [],
      warnings: ['File CSV cần có ít nhất 1 dòng tiêu đề cột và 1 dòng dữ liệu.'],
    };
  }

  const headers = rows[0]!.map((h) => h.trim());
  const dataRows = rows.slice(1, 16);
  if (rows.length - 1 > 15) {
    warnings.push('File CSV vượt quá 15 dòng; chỉ 15 dòng đầu tiên được nhập.');
  }

  const specs = dataRows.map((cols) => {
    const rec: Record<string, unknown> = {};
    headers.forEach((header, idx) => {
      rec[header] = cols[idx] ?? '';
    });
    return normalizeRecordToSpec(rec);
  });

  return { specs, warnings };
};

export const generateSampleBatchCsv = (): string => {
  const headers = [
    'customTitle',
    'senderName',
    'senderAccountNumber',
    'senderAvgTxVnd',
    'amountVnd',
    'splitTxCount',
    'channel',
    'recipientAccountNumber',
    'recipientOwnerName',
    'recipientAccountType',
    'recipientAccountAgeDays',
    'crossVictimFanInCount',
    'deviceIntegrity',
    'sessionSecurity',
    'inCallCoercionDetected',
    'deepfakeOrVirtualCamDetected',
    'apiConcurrentRequests100ms',
    'webhookHmacValid',
    'rawTranscript',
  ];

  const rows = [
    [
      '[Batch] Giả danh Shipper gửi link hoàn tiền 14.5M',
      'Trần Minh Thư',
      '0915222333',
      '750000',
      '14500000',
      '1',
      'VIETQR',
      '1903777666555',
      'LE VAN TUNG',
      'MULE_SUSPECT',
      '4',
      '2',
      'SHARED_EMULATOR_ROOTED',
      'BIOMETRIC_FACEID_PASSED',
      'true',
      'false',
      '1',
      'true',
      'Shipper giao hàng gọi điện báo bấm link hoàn tiền hội viên, chuyển gấp 14.500.000 đ vào STK 1903777666555.',
    ],
    [
      '[Batch] Thanh toán Học phí Đại học Quốc gia (An toàn)',
      'Nguyễn Hải Đăng',
      '0903444555',
      '900000',
      '22000000',
      '1',
      'VIETQR',
      '1188999000888',
      'DAI HOC QUOC GIA TPHCM',
      'TRUSTED_INSTITUTION',
      '1950',
      '0',
      'TRUSTED_PERSONAL_DEVICE',
      'BIOMETRIC_FACEID_PASSED',
      'false',
      'false',
      '1',
      'true',
      'Đóng học phí học kỳ 2 năm 2026 qua cổng VietQR nhà trường, không có dấu hiệu thao túng tâm lý.',
    ],
    [
      '[Batch] Chiếm đoạt Phiên ATO & Chia nhỏ 36M qua 3 lệnh',
      'Võ Thành Đạt',
      '0987666111',
      '800000',
      '36000000',
      '3',
      'P2P_WALLET',
      '1903111222333',
      'PHAM VAN DUNG',
      'MULE_SUSPECT',
      '3',
      '1',
      'SHARED_EMULATOR_ROOTED',
      'SESSION_SURVIVED_PASSWORD_RESET',
      'false',
      'false',
      '2',
      'true',
      'Phát hiện phiên sống sót sau đổi mật khẩu trên máy giả lập DEV-EMU-666 và chia nhỏ 3 lệnh 12M.',
    ],
  ];

  const escapeCell = (c: string) => `"${c.replace(/"/g, '""')}"`;
  return `\uFEFF${headers.join(',')}\n${rows.map((r) => r.map(escapeCell).join(',')).join('\n')}`;
};

export const exportCasesToCsv = (
  alerts: FraudAlert[],
  accounts: Account[],
  forensicsMap: Record<string, ForensicSuiteOutput>
): string => {
  const headers = [
    'AlertId',
    'Title',
    'ScenarioCode',
    'Status',
    'RiskScore',
    'Classification',
    'ZScoreDeviation',
    'SmurfingEntropy',
    'TargetAccountNumber',
    'TargetOwnerName',
    'DeepfakeVirtualCamDetected',
    'CreatedAt',
  ];

  const escapeCell = (v: string | number | boolean) => `"${String(v).replace(/"/g, '""')}"`;

  const lines = alerts.map((a) => {
    const f = forensicsMap[a.id];
    const targetAcc = accounts.find((acc) => acc.id === a.targetRecipientAccountId);
    const cyberStep = f?.toolTraceSteps.find((s) => s.toolName === 'inspect_cyber_session_logs');
    const deepfakeFlag = Boolean(
      cyberStep?.status === 'CRITICAL' && cyberStep.summaryVi.includes('DEEPFAKE')
    );
    return [
      a.id,
      a.title,
      a.scenarioCode,
      a.status,
      f?.deterministicRiskScore ?? a.deterministicRiskScore,
      f?.fallbackReport.classification ?? 'PENDING',
      f?.quantitativeMetrics.zScoreDeviation ?? 0,
      f?.quantitativeMetrics.smurfingEntropyIndex ?? 0,
      targetAcc?.accountNumber ?? a.targetRecipientAccountId,
      targetAcc?.ownerName ?? a.targetRecipientAccountId,
      deepfakeFlag,
      a.createdAt,
    ]
      .map(escapeCell)
      .join(',');
  });

  return `\uFEFF${headers.join(',')}\n${lines.join('\n')}`;
};
