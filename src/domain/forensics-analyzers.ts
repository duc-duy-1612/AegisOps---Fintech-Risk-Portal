import {
  buildHitlContextSignature,
  evaluateAdaptiveHitlFeedback,
} from './hitl-feedback-engine';
import type {
  Account,
  ApiSecurityEvent,
  AuthSessionLog,
  CaseClassification,
  DeviceFingerprint,
  EvidenceArtifact,
  FlowVelocityStatus,
  ForensicSuiteOutput,
  ForensicToolStep,
  FraudAlert,
  GraphEdgeItem,
  GraphNodeItem,
  HitlFeedbackMemoryRecord,
  InvestigationReport,
  PlaybookActionItem,
  QuantitativeGraphMetrics,
  RiskAttributionFactor,
  ShieldRule,
  Transaction,
  UrlThreatFinding,
} from './types';

const OFFICIAL_SAFE_DOMAINS = [
  'momo.vn',
  'dichvucong.gov.vn',
  'chinhphu.vn',
  'bocongan.gov.vn',
  'bachmai.gov.vn',
  'choray.vn',
];

const SPOOF_BRAND_ROOTS = [
  { keyword: 'cong-an', target: 'Cổng Thông tin Bộ Công an (.gov.vn)' },
  { keyword: 'bocongan', target: 'Bộ Công an (.gov.vn)' },
  { keyword: 'dichvucong', target: 'Cổng Dịch vụ công Quốc gia (.gov.vn)' },
  { keyword: 'vneid', target: 'Ứng dụng Định danh Quốc gia VNeID' },
  { keyword: 'momo', target: 'Ví Điện tử MoMo Chính thức (momo.vn)' },
  { keyword: 'hoantien', target: 'Cổng Hoàn tiền Giả mạo' },
  { keyword: 'baomat', target: 'Cổng Bảo mật Giả mạo' },
  { keyword: 'xacminh', target: 'Cổng Xác minh Giả mạo' },
];

export const inspectMaliciousUrlsAndApks = (text: string): UrlThreatFinding[] => {
  const matches = text.match(/https?:\/\/[^\s"'<>]+/gi) ?? [];
  const seen = new Set<string>();
  const findings: UrlThreatFinding[] = [];

  for (const rawUrl of matches) {
    const cleanUrl = rawUrl.replace(/[.,;!?)]+$/, '');
    if (seen.has(cleanUrl)) continue;
    seen.add(cleanUrl);

    const lowerUrl = cleanUrl.toLowerCase();
    const isPlainHttp = lowerUrl.startsWith('http://');
    const isApkPayload = lowerUrl.includes('.apk');

    let domain = cleanUrl;
    try {
      domain = new URL(cleanUrl).hostname.toLowerCase();
    } catch {
      domain = lowerUrl.replace(/^https?:\/\//, '').split('/')[0] ?? cleanUrl;
    }

    const isOfficial = OFFICIAL_SAFE_DOMAINS.some(
      (safe) => domain === safe || domain.endsWith(`.${safe}`)
    );
    const spoofMatch = !isOfficial
      ? SPOOF_BRAND_ROOTS.find((s) => domain.includes(s.keyword) || lowerUrl.includes(s.keyword))
      : undefined;

    if (isApkPayload || spoofMatch || (!isOfficial && isPlainHttp)) {
      const score = Math.min(
        99,
        (isApkPayload ? 48 : 0) + (spoofMatch ? 38 : 18) + (isPlainHttp ? 12 : 0)
      );
      findings.push({
        url: cleanUrl,
        domain,
        isApkPayload,
        isPlainHttp,
        typosquattingTarget: spoofMatch?.target,
        riskScore: score,
        verdict: isApkPayload || spoofMatch ? 'MALICIOUS_APK_PHISHING' : 'SUSPICIOUS_DOMAIN',
        reasonVi: [
          isApkPayload ? 'Tệp cài đặt .APK ngoài Play Store (nguy cơ chiếm quyền Accessibility)' : null,
          spoofMatch ? `Giả mạo tên miền (Typosquatting) thương hiệu ${spoofMatch.target}` : null,
          isPlainHttp ? 'Dùng giao thức HTTP không mã hóa SSL' : null,
        ]
          .filter(Boolean)
          .join(' • '),
      });
    } else if (isOfficial) {
      findings.push({
        url: cleanUrl,
        domain,
        isApkPayload: false,
        isPlainHttp: false,
        riskScore: 4,
        verdict: 'SAFE_OFFICIAL',
        reasonVi: `Tên miền chính thức đã xác thực (${domain}).`,
      });
    }
  }

  return findings;
};

export interface ForensicContext {
  alert: FraudAlert;
  accounts: Account[];
  devices: DeviceFingerprint[];
  authLogs: AuthSessionLog[];
  transactions: Transaction[];
  apiEvents: ApiSecurityEvent[];
  evidences: EvidenceArtifact[];
  feedbackMemory?: HitlFeedbackMemoryRecord[];
  targetFingerprintsByAccountId?: Record<string, string>;
  legacyTargetFingerprintsByAccountId?: Record<string, string[]>;
  activeShieldRules?: ShieldRule[];
  nowMs?: number;
}

const SCAM_KEYWORDS = [
  'công an',
  'điều tra',
  'tạm giữ',
  'xác minh tài sản',
  'hoàn tiền',
  'shipper',
  'bấm link',
  'chuyển gấp',
  'giữ bí mật',
  'cộng tác viên',
  'hoa hồng',
  'khóa tài khoản',
  'chuyển nhầm',
];

/**
 * Deduplicates transaction records by canonical transaction ID and idempotencyKey
 * so duplicate event ingestion cannot artificially inflate Z-Score, Smurfing counts, or velocity.
 */
export const deduplicateAlertTransactions = (
  transactions: readonly Transaction[]
): Transaction[] => {
  const seenIds = new Set<string>();
  const seenIdemKeys = new Set<string>();
  const unique: Transaction[] = [];

  for (const tx of transactions) {
    if (tx.txKind === 'CLAWBACK_REVERSAL') continue;
    const normId = tx.id.trim().toUpperCase();
    const normIdem = tx.idempotencyKey?.trim().toUpperCase();
    if (normId && seenIds.has(normId)) continue;
    if (normIdem && seenIdemKeys.has(normIdem)) continue;
    if (normId) seenIds.add(normId);
    if (normIdem) seenIdemKeys.add(normIdem);
    unique.push(tx);
  }

  return unique;
};

export const analyzeAccountProfile = (ctx: ForensicContext): ForensicToolStep => {
  const account = ctx.accounts.find((a) => a.id === ctx.alert.primaryAccountId);
  const alertTxs = deduplicateAlertTransactions(
    ctx.transactions.filter((t) => t.alertId === ctx.alert.id)
  );
  if (alertTxs.length === 0) {
    return {
      toolName: 'query_account_profile',
      labelVi: 'Phân tích thống kê Z-Score hạn mức & hồ sơ KYC',
      status: 'WARNING',
      durationMs: 18,
      summaryVi: account
        ? `Chủ TK ${account.ownerName} (${account.kycLevel}): Chưa có giao dịch liên kết (0 bản ghi) để tính Z-Score — dữ liệu thiếu, không tự động coi là an toàn.`
        : 'Không tìm thấy hồ sơ tài khoản nguồn và chưa có giao dịch liên kết (dữ liệu thiếu).',
      evidenceIds: [],
      riskContribution: 5,
    };
  }

  const totalOutflow = alertTxs.reduce((sum, t) => sum + t.amountVnd, 0);
  const avgTx = account?.avgTxAmountVnd ?? 500_000;
  const stdDev = Math.max(250_000, avgTx * 0.45);
  const zScore = Number(((totalOutflow - avgTx) / stdDev).toFixed(1));
  const zSign = zScore >= 0 ? `+${zScore}` : `${zScore}`;
  const ratio = avgTx > 0 ? Number((totalOutflow / avgTx).toFixed(1)) : 1;

  const isAnomaly = ratio >= 7 || zScore >= 6;
  return {
    toolName: 'query_account_profile',
    labelVi: 'Phân tích thống kê Z-Score hạn mức & hồ sơ KYC',
    status: isAnomaly ? 'WARNING' : 'SUCCESS',
    durationMs: 18,
    summaryVi: account
      ? `Chủ TK ${account.ownerName} (${account.kycLevel}): Tổng dòng tiền ra ${totalOutflow.toLocaleString('vi-VN')} ₫ (${alertTxs.length} GD duy nhất, gấp ${ratio}x TB, độ lệch chuẩn Z-Score = ${zSign}σ).`
      : 'Không tìm thấy hồ sơ gốc; sử dụng ngưỡng mặc định.',
    evidenceIds: alertTxs.map((t) => t.id),
    riskContribution: isAnomaly ? 22 : 5,
  };
};

export interface FlowVelocityEvaluation {
  velocityVndPerMin: number;
  status: FlowVelocityStatus;
  elapsedMinutes: number;
  totalAmountVnd: number;
  validTimestampCount: number;
  invalidTimestampCount: number;
}

export const evaluateFlowVelocityMetrics = (
  transactions: readonly Transaction[]
): FlowVelocityEvaluation => {
  const uniqueTransactions = deduplicateAlertTransactions(transactions);
  if (uniqueTransactions.length === 0) {
    return {
      velocityVndPerMin: 0,
      status: 'NO_TRANSACTIONS',
      elapsedMinutes: 0,
      totalAmountVnd: 0,
      validTimestampCount: 0,
      invalidTimestampCount: 0,
    };
  }

  let totalAmountVnd = 0;
  const parsedMs: number[] = [];
  let invalidTimestampCount = 0;

  for (const tx of uniqueTransactions) {
    totalAmountVnd += Math.max(0, Math.round(tx.amountVnd || 0));
    const rawTs = typeof tx.timestamp === 'string' ? tx.timestamp.trim() : '';
    const ms = rawTs ? Date.parse(rawTs) : Number.NaN;
    if (Number.isFinite(ms)) {
      parsedMs.push(ms);
    } else {
      invalidTimestampCount += 1;
    }
  }

  if (invalidTimestampCount > 0 || parsedMs.length === 0) {
    return {
      velocityVndPerMin: 0,
      status: 'INVALID_TIMESTAMP_DATA',
      elapsedMinutes: 0,
      totalAmountVnd,
      validTimestampCount: parsedMs.length,
      invalidTimestampCount,
    };
  }

  if (parsedMs.length === 1) {
    return {
      velocityVndPerMin: 0,
      status: 'SINGLE_EVENT_NO_WINDOW',
      elapsedMinutes: 0,
      totalAmountVnd,
      validTimestampCount: 1,
      invalidTimestampCount: 0,
    };
  }

  const minMs = Math.min(...parsedMs);
  const maxMs = Math.max(...parsedMs);
  const elapsedMs = maxMs - minMs;

  if (elapsedMs <= 0) {
    return {
      velocityVndPerMin: 0,
      status: 'ZERO_ELAPSED_TIME',
      elapsedMinutes: 0,
      totalAmountVnd,
      validTimestampCount: parsedMs.length,
      invalidTimestampCount: 0,
    };
  }

  const elapsedMinutes = elapsedMs / 60_000;
  return {
    velocityVndPerMin: Math.round(totalAmountVnd / elapsedMinutes),
    status: 'MEASURED_INTERVAL',
    elapsedMinutes,
    totalAmountVnd,
    validTimestampCount: parsedMs.length,
    invalidTimestampCount: 0,
  };
};

const computeGraphStructureMetrics = (
  ctx: ForensicContext
): {
  smurfingEntropyIndex: number;
  deviceBipartiteClusterScore: number;
} => {
  const targetAcc = ctx.accounts.find((a) => a.id === ctx.alert.targetRecipientAccountId);
  const alertTxs = deduplicateAlertTransactions(
    ctx.transactions.filter((t) => t.alertId === ctx.alert.id)
  );
  const senderTxs = alertTxs.filter((t) => t.senderAccountId === ctx.alert.primaryAccountId);
  const txsForSmurfing = senderTxs.length >= 2 ? senderTxs : alertTxs;

  let smurfingEntropyIndex = 0.12;
  if (txsForSmurfing.length >= 2) {
    const smurfTotal = txsForSmurfing.reduce((s, t) => s + t.amountVnd, 0);
    const mean = smurfTotal / txsForSmurfing.length;
    const variance =
      txsForSmurfing.reduce((acc, t) => acc + Math.pow(t.amountVnd - mean, 2), 0) /
      txsForSmurfing.length;
    const cv = mean > 0 ? Math.sqrt(variance) / mean : 1;
    smurfingEntropyIndex = Number(Math.max(0.1, Math.min(0.99, 1 - cv)).toFixed(2));
  }

  const targetDev = ctx.devices.find((d) => d.id === targetAcc?.primaryDeviceId);
  const deviceBipartiteClusterScore = targetDev
    ? Number(
      Math.min(
        0.98,
        (targetDev.linkedAccountIds.length / 4) * (targetDev.isEmulatorOrRooted ? 1.15 : 0.6)
      ).toFixed(2)
    )
    : 0.05;

  return { smurfingEntropyIndex, deviceBipartiteClusterScore };
};

export const analyzeMuleGraph = (
  ctx: ForensicContext
): { step: ForensicToolStep; nodes: GraphNodeItem[]; edges: GraphEdgeItem[] } => {
  const alertTxs = deduplicateAlertTransactions(
    ctx.transactions.filter((t) => t.alertId === ctx.alert.id)
  );
  const nodes: GraphNodeItem[] = [];
  const edges: GraphEdgeItem[] = [];
  const addedNodes = new Set<string>();
  const evidenceIds: string[] = [];

  const primaryAcc = ctx.accounts.find((a) => a.id === ctx.alert.primaryAccountId);
  if (primaryAcc) {
    nodes.push({
      id: primaryAcc.id,
      label: primaryAcc.ownerName,
      sublabel: `${primaryAcc.id} • ${primaryAcc.bankOrWalletName}`,
      nodeKind: 'VICTIM',
      riskLevel: 'MEDIUM',
      metadata: { kyc: primaryAcc.kycLevel, avgTxVnd: primaryAcc.avgTxAmountVnd },
      position: { x: 30, y: 80 },
    });
    addedNodes.add(primaryAcc.id);
  }

  // Ensure ALL cross-victim senders in alert transactions are rendered as nodes on the graph
  let victimOffset = 1;
  alertTxs.forEach((tx) => {
    if (!addedNodes.has(tx.senderAccountId)) {
      const senderAcc = ctx.accounts.find((a) => a.id === tx.senderAccountId);
      if (senderAcc) {
        nodes.push({
          id: senderAcc.id,
          label: senderAcc.ownerName,
          sublabel: `${senderAcc.id} • ${senderAcc.bankOrWalletName}`,
          nodeKind: 'VICTIM',
          riskLevel: 'MEDIUM',
          evidenceId: tx.id,
          metadata: { kyc: senderAcc.kycLevel, avgTxVnd: senderAcc.avgTxAmountVnd },
          position: { x: 30, y: 80 + victimOffset * 130 },
        });
        addedNodes.add(senderAcc.id);
        victimOffset += 1;
      }
    }
  });

  let sharedDeviceMuleCount = 0;
  alertTxs.forEach((tx, idx) => {
    evidenceIds.push(tx.id);
    const receiver = ctx.accounts.find((a) => a.id === tx.receiverAccountId);
    if (receiver && !addedNodes.has(receiver.id)) {
      const isTrusted = receiver.accountType === 'TRUSTED_INSTITUTION';
      const isMule = receiver.accountType === 'MULE_SUSPECT';
      nodes.push({
        id: receiver.id,
        label: receiver.ownerName,
        sublabel: `${receiver.accountNumber} (${receiver.bankOrWalletName})`,
        nodeKind: isTrusted ? 'TRUSTED_PARTNER' : 'SUSPECT_MULE',
        riskLevel: isTrusted ? 'SAFE' : isMule ? 'CRITICAL' : 'HIGH',
        evidenceId: tx.id,
        metadata: { status: receiver.status, accountType: receiver.accountType },
        position: { x: 360, y: 40 + idx * 120 },
      });
      addedNodes.add(receiver.id);

      const dev = ctx.devices.find((d) => d.id === receiver.primaryDeviceId);
      if (dev && (dev.linkedAccountIds.length >= 2 || dev.isEmulatorOrRooted)) {
        sharedDeviceMuleCount += 1;
        if (!addedNodes.has(dev.id)) {
          nodes.push({
            id: dev.id,
            label: `Thiết bị cụm: ${dev.id}`,
            sublabel: `${dev.osBrowser} • IP ${dev.ipAddress}`,
            nodeKind: 'SHARED_DEVICE',
            riskLevel: 'CRITICAL',
            evidenceId: dev.id,
            metadata: { emulator: dev.isEmulatorOrRooted, sharedAccounts: dev.linkedAccountIds.length },
            position: { x: 690, y: 90 },
          });
          addedNodes.add(dev.id);
          evidenceIds.push(dev.id);
        }
        edges.push({
          id: `edge-${receiver.id}-${dev.id}`,
          source: receiver.id,
          target: dev.id,
          label: `Dùng chung máy (${dev.linkedAccountIds.length} TK)`,
          animated: true,
          edgeKind: 'DEVICE_LINK',
          isHighRisk: true,
        });

        // Also surface sibling co-conspirator Mule accounts sharing the exact same emulator device
        dev.linkedAccountIds.forEach((siblingAccId, sibIdx) => {
          if (!addedNodes.has(siblingAccId)) {
            const sibAcc = ctx.accounts.find((a) => a.id === siblingAccId);
            if (sibAcc) {
              nodes.push({
                id: sibAcc.id,
                label: `${sibAcc.ownerName} (Đồng phạm)`,
                sublabel: `${sibAcc.accountNumber} • Cùng máy ${dev.id}`,
                nodeKind: 'SUSPECT_MULE',
                riskLevel: 'HIGH',
                evidenceId: dev.id,
                metadata: { status: sibAcc.status, sharedDevice: dev.id },
                position: { x: 690, y: 220 + sibIdx * 105 },
              });
              addedNodes.add(sibAcc.id);
              edges.push({
                id: `edge-sib-${dev.id}-${sibAcc.id}`,
                source: dev.id,
                target: sibAcc.id,
                label: 'TK Mule đồng phạm cùng thiết bị',
                animated: true,
                edgeKind: 'DEVICE_LINK',
                isHighRisk: true,
              });
            }
          }
        });
      }
    }

    edges.push({
      id: tx.id,
      source: tx.senderAccountId,
      target: tx.receiverAccountId,
      label: `${tx.amountVnd.toLocaleString('vi-VN')} ₫ (Hop ${tx.hopIndex})`,
      animated: true,
      edgeKind: 'MONEY_FLOW',
      isHighRisk: receiver?.accountType !== 'TRUSTED_INSTITUTION',
    });
  });

  const isSmurfing = alertTxs.length >= 3;
  const isCriticalGraph = sharedDeviceMuleCount >= 2 || isSmurfing;
  const { smurfingEntropyIndex, deviceBipartiteClusterScore } = computeGraphStructureMetrics(ctx);
  const targetAcc = ctx.accounts.find((a) => a.id === ctx.alert.targetRecipientAccountId);
  const isTrustedPartnerTarget = targetAcc?.accountType === 'TRUSTED_INSTITUTION';

  const step: ForensicToolStep = {
    toolName: 'trace_money_flow_graph',
    labelVi: 'Truy vết đồ thị BFS, Smurfing Entropy & hệ số gom cụm Mule Ring',
    status: isCriticalGraph ? 'CRITICAL' : sharedDeviceMuleCount === 1 || alertTxs.length === 0 ? 'WARNING' : 'SUCCESS',
    durationMs: 34,
    summaryVi: isCriticalGraph
      ? `Phát hiện cấu trúc chia nhỏ dòng tiền Smurfing (${alertTxs.length} lệnh duy nhất, Entropy = ${smurfingEntropyIndex.toFixed(2)}, Cluster = ${deviceBipartiteClusterScore.toFixed(2)}) chảy vào cụm ${sharedDeviceMuleCount} TK Mule dùng chung thiết bị.`
      : sharedDeviceMuleCount === 1
        ? `Tài khoản đích nằm trong cụm thiết bị giả lập dùng chung (Bipartite Cluster = ${deviceBipartiteClusterScore.toFixed(2)}, Entropy = ${smurfingEntropyIndex.toFixed(2)}).`
        : alertTxs.length === 0
          ? 'Chưa có bản ghi giao dịch liên kết trên đồ thị dòng tiền (dữ liệu thiếu — không coi là xác nhận an toàn).'
          : isTrustedPartnerTarget
            ? `Đồ thị dòng tiền 1-1 tới đối tác tổ chức đã xác thực (Bipartite Cluster = ${deviceBipartiteClusterScore.toFixed(2)}, Entropy = ${smurfingEntropyIndex.toFixed(2)}).`
            : `Đồ thị dòng tiền 1-1 chưa ghi nhận cụm thiết bị dùng chung (Bipartite Cluster = ${deviceBipartiteClusterScore.toFixed(2)}, Entropy = ${smurfingEntropyIndex.toFixed(2)}; tài khoản đích chưa thuộc danh sách tổ chức uy tín).`,
    evidenceIds: Array.from(new Set(evidenceIds)),
    riskContribution: isCriticalGraph ? 34 : sharedDeviceMuleCount === 1 ? 24 : 0,
  };

  return { step, nodes, edges };
};

export const inspectCyberSession = (ctx: ForensicContext): ForensicToolStep => {
  const logs = ctx.authLogs.filter((l) => l.accountId === ctx.alert.primaryAccountId);
  const survivedResetLogs = logs.filter((l) => l.survivedCredentialReset || l.eventType === 'SESSION_SURVIVED_RESET');
  const replayLogs = logs.filter((l) => l.eventType === 'REFRESH_TOKEN_REPLAY');
  const deepfakeLogs = logs.filter((l) => l.eventType === 'DEEPFAKE_VIRTUAL_CAM_INJECTION');
  const biometricPass = logs.some((l) => l.eventType === 'BIOMETRIC_STEP_UP_PASS');

  const hasAtoChain = survivedResetLogs.length > 0 || replayLogs.length > 0 || deepfakeLogs.length > 0;
  return {
    toolName: 'inspect_cyber_session_logs',
    labelVi: 'Kiểm tra ATO, Refresh Token Replay & Tín hiệu mô phỏng PAD (tham chiếu ISO 30107-3)',
    status: hasAtoChain ? 'CRITICAL' : logs.length === 0 ? 'WARNING' : 'SUCCESS',
    durationMs: 26,
    summaryVi:
      deepfakeLogs.length > 0
        ? `CẢNH BÁO DEEPFAKE / CAMERA ẢO (Tín hiệu mô phỏng): Phát hiện chèn video giả mạo vào luồng FaceID (tham chiếu chuẩn ISO/IEC 30107-3 Liveness PAD — chưa chứng nhận lab) kết hợp ${survivedResetLogs.length} phiên bất thường.`
        : hasAtoChain
          ? `CẢNH BÁO ATO: Phát hiện ${survivedResetLogs.length} phiên cũ sống sót sau khi đổi mật khẩu & ${replayLogs.length} lần Replay Refresh Token từ thiết bị giả lập.`
          : logs.length === 0
            ? 'Chưa có log phiên đăng nhập / xác thực cho tài khoản nguồn (telemetry trống — không coi là bằng chứng an toàn).'
            : biometricPass
              ? 'Phiên đăng nhập chính chủ có tín hiệu mô phỏng 3D Liveness PAD (tham chiếu ISO/IEC 30107-3 — chưa chứng nhận) & FaceID hợp lệ.'
              : 'Chưa phát hiện dấu hiệu chiếm đoạt phiên hoặc giả mạo camera trong các log hiện có.',
    evidenceIds: logs.map((l) => l.id),
    riskContribution: deepfakeLogs.length > 0 ? 44 : hasAtoChain ? 36 : 0,
  };
};

export const detectBusinessLogicAbuse = (
  ctx: ForensicContext,
  graphNodes: GraphNodeItem[],
  graphEdges: GraphEdgeItem[]
): ForensicToolStep => {
  const events = ctx.apiEvents.filter((e) => e.alertId === ctx.alert.id);
  const raceEvents = events.filter((e) => e.concurrentRequests100ms >= 5 || e.anomalyClass === 'RACE_CONDITION_TOCTOU');
  const spoofEvents = events.filter((e) => !e.hmacSignatureValid || e.anomalyClass === 'WEBHOOK_SPOOF');

  events.forEach((evt) => {
    if (evt.concurrentRequests100ms >= 5 || !evt.hmacSignatureValid) {
      const nodeId = `API-${evt.id}`;
      graphNodes.push({
        id: nodeId,
        label: evt.endpoint,
        sublabel: `${evt.concurrentRequests100ms} req/100ms • HMAC: ${evt.hmacSignatureValid ? 'OK' : 'INVALID'}`,
        nodeKind: 'API_ENDPOINT',
        riskLevel: 'CRITICAL',
        evidenceId: evt.id,
        metadata: { burst: evt.concurrentRequests100ms, hmacValid: evt.hmacSignatureValid },
        position: { x: 640, y: 80 },
      });
      graphEdges.push({
        id: `edge-api-${evt.id}`,
        source: evt.accountId,
        target: nodeId,
        label: `${evt.anomalyClass} (${evt.concurrentRequests100ms}x burst)`,
        animated: true,
        edgeKind: 'API_BURST',
        isHighRisk: true,
      });
    }
  });

  const hasExploit = raceEvents.length > 0 || spoofEvents.length > 0;
  const isCompoundExploit =
    (raceEvents.length > 0 && spoofEvents.length > 0) ||
    (raceEvents[0]?.concurrentRequests100ms ?? 0) >= 10;
  return {
    toolName: 'detect_business_logic_abuse',
    labelVi: 'Phân tích xung đột Race Condition (TOCTOU) & chữ ký Webhook HMAC',
    status: hasExploit ? 'CRITICAL' : 'SUCCESS',
    durationMs: 22,
    summaryVi: hasExploit
      ? `Phát hiện khai thác Race Condition (${raceEvents[0]?.concurrentRequests100ms ?? 0} request đồng thời/100ms) và ${spoofEvents.length} callback thiếu chữ ký HMAC hợp lệ.`
      : 'Không có xung đột đồng thời (TOCTOU) hay giả mạo chữ ký Webhook.',
    evidenceIds: events.map((e) => e.id),
    riskContribution: isCompoundExploit ? 66 : hasExploit ? 48 : 0,
  };
};

export const correlateScamCampaign = (ctx: ForensicContext): ForensicToolStep => {
  const evidences = ctx.evidences.filter((e) => e.alertId === ctx.alert.id);
  const targetAcc = ctx.accounts.find((a) => a.id === ctx.alert.targetRecipientAccountId);
  const isTrustedInstitution = targetAcc?.accountType === 'TRUSTED_INSTITUTION';

  const matchedKeywords = new Set<string>();
  evidences.forEach((ev) => {
    const lower = ev.textContent.toLowerCase();
    SCAM_KEYWORDS.forEach((kw) => {
      if (lower.includes(kw)) matchedKeywords.add(kw);
    });
    if (!isTrustedInstitution) {
      ev.extractedSignals.forEach((sig) => {
        if (!sig.toLowerCase().includes('0 dấu hiệu') && !sig.toLowerCase().includes('uy tín')) {
          matchedKeywords.add(sig);
        }
      });
    }
  });

  const targetAccId = ctx.alert.targetRecipientAccountId;
  const crossVictimSenders = new Set(
    ctx.transactions.filter((t) => t.receiverAccountId === targetAccId).map((t) => t.senderAccountId)
  );

  const combinedText = evidences.map((e) => `${e.title} ${e.textContent}`).join(' ');
  const urlFindings = inspectMaliciousUrlsAndApks(combinedText);
  const maliciousUrls = urlFindings.filter((u) => u.verdict !== 'SAFE_OFFICIAL');

  const isScamCampaign =
    !isTrustedInstitution &&
    (matchedKeywords.size >= 2 || crossVictimSenders.size >= 2 || maliciousUrls.length > 0);
  return {
    toolName: 'correlate_scam_campaign',
    labelVi: 'Liên kết chiến dịch đa nạn nhân (Fan-In) & Quét Link Phishing / .APK',
    status: isScamCampaign ? 'CRITICAL' : 'SUCCESS',
    durationMs: 29,
    summaryVi: isScamCampaign
      ? `Tài khoản đích ${targetAccId} có chỉ số Fan-In = ${crossVictimSenders.size} nạn nhân độc lập; phát hiện ${matchedKeywords.size} tín hiệu thao túng tâm lý${maliciousUrls.length > 0 ? ` và ${maliciousUrls.length} URL/APK giả mạo (${maliciousUrls[0]?.domain})` : ''}.`
      : isTrustedInstitution
        ? 'Đối tác thụ hưởng thuộc nhóm tổ chức đã xác thực trong danh mục mô phỏng; 0 mẫu hội thoại thao túng tâm lý hoặc URL độc hại.'
        : 'Chưa ghi nhận tín hiệu chiến dịch đa nạn nhân hoặc URL/APK độc hại trong dữ liệu hiện có (cần đối chiếu thêm nếu thiếu bằng chứng hội thoại).',
    evidenceIds: evidences.map((e) => e.id),
    riskContribution: isScamCampaign ? (maliciousUrls.some((u) => u.isApkPayload) ? 45 : 40) : 0,
  };
};

const computeExplainableRiskAndMetrics = (
  ctx: ForensicContext,
  steps: ForensicToolStep[]
): {
  finalScore: number;
  factors: RiskAttributionFactor[];
  metrics: QuantitativeGraphMetrics;
} => {
  const account = ctx.accounts.find((a) => a.id === ctx.alert.primaryAccountId);
  const targetAcc = ctx.accounts.find((a) => a.id === ctx.alert.targetRecipientAccountId);
  const alertTxs = deduplicateAlertTransactions(
    ctx.transactions.filter((t) => t.alertId === ctx.alert.id)
  );
  const totalOutflow = alertTxs.reduce((s, t) => s + t.amountVnd, 0);
  const avgTx = account?.avgTxAmountVnd ?? 800_000;
  const stdDev = Math.max(250_000, avgTx * 0.45);
  const zScoreDeviation =
    alertTxs.length > 0 ? Number(((totalOutflow - avgTx) / stdDev).toFixed(1)) : 0;

  const { smurfingEntropyIndex, deviceBipartiteClusterScore } = computeGraphStructureMetrics(ctx);

  const crossVictimFanIn = new Set(
    ctx.transactions
      .filter((t) => t.receiverAccountId === ctx.alert.targetRecipientAccountId)
      .map((t) => t.senderAccountId)
  ).size;

  const velocityEval = evaluateFlowVelocityMetrics(alertTxs);
  const flowVelocityVndPerMin = velocityEval.velocityVndPerMin;
  const flowVelocityStatus = velocityEval.status;

  const factors: RiskAttributionFactor[] = [];
  steps.forEach((st) => {
    if (st.riskContribution > 0) {
      factors.push({
        id: `BOOST-${st.toolName}`,
        labelVi: st.labelVi,
        deltaScore: st.riskContribution,
        kind: 'RISK_BOOSTER',
        metricDetail:
          st.toolName === 'query_account_profile'
            ? `Z-Score = +${zScoreDeviation}σ`
            : st.toolName === 'trace_money_flow_graph'
              ? `Smurfing Entropy = ${smurfingEntropyIndex} | Cluster = ${deviceBipartiteClusterScore}`
              : st.toolName === 'correlate_scam_campaign'
                ? `Cross-Victim Fan-In = ${crossVictimFanIn} nạn nhân`
                : 'Tín hiệu kỹ thuật mức CRITICAL',
      });
    }
  });

  // Add Human-Centered Trust Dampeners (Negative weights that prevent false-positive lockouts)
  const hasBiometricPass = ctx.authLogs.some(
    (l) => l.accountId === ctx.alert.primaryAccountId && l.eventType === 'BIOMETRIC_STEP_UP_PASS'
  );
  const hasAto = ctx.authLogs.some(
    (l) =>
      l.accountId === ctx.alert.primaryAccountId &&
      (l.survivedCredentialReset || l.eventType === 'DEEPFAKE_VIRTUAL_CAM_INJECTION')
  );

  if (targetAcc?.accountType === 'TRUSTED_INSTITUTION') {
    factors.push({
      id: 'DAMP-TRUSTED-INST',
      labelVi: 'Giảm trừ Uy tín: Đơn vị thụ hưởng là Bệnh viện / Tổ chức đã xác thực',
      deltaScore: -22,
      kind: 'TRUST_DAMPENER',
      metricDetail: '0 liên kết Mule Ring • Đối tác VietQR Y tế',
    });
  }

  if (hasBiometricPass && !hasAto && targetAcc?.accountType === 'TRUSTED_INSTITUTION') {
    factors.push({
      id: 'DAMP-BIOMETRIC-KYC',
      labelVi: 'Giảm trừ Chính chủ: Đã qua xác thực FaceID + NFC CCCD hợp lệ',
      deltaScore: -16,
      kind: 'TRUST_DAMPENER',
      metricDetail: `KYC Level 2 • Thâm niên TK ${account?.accountAgeDays ?? 1000} ngày`,
    });
  }

  const netFromFactors = factors.reduce((sum, f) => sum + f.deltaScore, 0);
  const hasTrustedDampeners = factors.some((f) => f.kind === 'TRUST_DAMPENER');
  const hasCriticalTechStep = steps.some(
    (s) =>
      (s.toolName === 'inspect_cyber_session_logs' || s.toolName === 'detect_business_logic_abuse') &&
      s.status === 'CRITICAL'
  );
  const isSafeFp =
    !hasAto &&
    !hasCriticalTechStep &&
    (ctx.alert.scenarioCode === 'SMART_FALSE_POSITIVE' ||
      (targetAcc?.accountType === 'TRUSTED_INSTITUTION' && netFromFactors <= 0));
  const finalScore = isSafeFp
    ? Math.max(8, Math.min(22, 30 + netFromFactors))
    : ctx.alert.scenarioCode === 'CUSTOM_SANDBOX'
      ? Math.max(12, Math.min(99, hasTrustedDampeners ? 30 + netFromFactors : Math.max(18, netFromFactors)))
      : Math.min(99, Math.max(ctx.alert.deterministicRiskScore, netFromFactors));

  return {
    finalScore,
    factors,
    metrics: {
      zScoreDeviation,
      flowVelocityVndPerMin,
      flowVelocityStatus,
      smurfingEntropyIndex,
      deviceBipartiteClusterScore,
      crossVictimFanIn,
    },
  };
};

export const runDeterministicForensicsSuite = (ctx: ForensicContext): ForensicSuiteOutput => {
  const step1 = analyzeAccountProfile(ctx);
  const { step: step2, nodes, edges } = analyzeMuleGraph(ctx);
  const step3 = inspectCyberSession(ctx);
  const step4 = detectBusinessLogicAbuse(ctx, nodes, edges);
  const step5 = correlateScamCampaign(ctx);

  const steps = [step1, step2, step3, step4, step5];
  const { finalScore: baseRiskScore, factors, metrics } =
    computeExplainableRiskAndMetrics(ctx, steps);

  const combinedEvidenceText = ctx.evidences
    .filter((e) => e.alertId === ctx.alert.id)
    .map((e) => `${e.title} ${e.textContent}`)
    .join(' ');
  const urlThreatFindings = inspectMaliciousUrlsAndApks(combinedEvidenceText);

  const targetAcc = ctx.accounts.find((a) => a.id === ctx.alert.targetRecipientAccountId);
  const alertTxs = ctx.transactions.filter((t) => t.alertId === ctx.alert.id);
  const hasActiveHardShield = Boolean(
    targetAcc?.status === 'FROZEN' ||
    ctx.activeShieldRules?.some(
      (r) =>
        r.active &&
        (r.targetAccountId === ctx.alert.targetRecipientAccountId ||
          (targetAcc && r.targetAccountNumber === targetAcc.accountNumber))
    )
  );
  const hasMaliciousUrlSignals = urlThreatFindings.some((u) => u.verdict !== 'SAFE_OFFICIAL');
  const hardCriticalSignalsPresent =
    step3.status === 'CRITICAL' ||
    step4.status === 'CRITICAL' ||
    hasActiveHardShield ||
    (hasMaliciousUrlSignals && ctx.alert.scenarioCode !== 'SMART_FALSE_POSITIVE');

  const targetFingerprint =
    ctx.targetFingerprintsByAccountId?.[ctx.alert.targetRecipientAccountId] ??
    ctx.alert.targetRecipientAccountId;
  const currentContextSignature = buildHitlContextSignature({
    scenarioCode: ctx.alert.scenarioCode,
    recipientAccountType: targetAcc?.accountType,
    channel: alertTxs[0]?.channel,
  });

  const adaptiveResult = evaluateAdaptiveHitlFeedback({
    baseScore: baseRiskScore,
    alert: ctx.alert,
    targetAccount: targetAcc,
    targetFingerprint,
    legacyTargetFingerprints:
      ctx.legacyTargetFingerprintsByAccountId?.[ctx.alert.targetRecipientAccountId],
    currentContextSignature,
    feedbackMemory: ctx.feedbackMemory ?? [],
    hardCriticalSignalsPresent,
    nowMs: ctx.nowMs,
  });

  const deterministicRiskScore = adaptiveResult.finalScore;
  const combinedFactors = [...factors, ...adaptiveResult.factors];
  const hasAppliedForceBlock = adaptiveResult.summary.appliedRecords.some(
    (r) => r.feedbackDecision === 'FORCE_BLOCK'
  );

  const isSafeFp =
    deterministicRiskScore < 28 &&
    !hasAppliedForceBlock &&
    !hasActiveHardShield &&
    step3.status === 'SUCCESS' &&
    step4.status === 'SUCCESS' &&
    !adaptiveResult.summary.conflictDetected;

  const evidenceLabelMap: Record<string, string> = {};
  ctx.transactions.filter((t) => t.alertId === ctx.alert.id).forEach((t) => {
    evidenceLabelMap[t.id] = `Giao dịch ${t.id} (${t.amountVnd.toLocaleString('vi-VN')} ₫ → ${t.receiverAccountId})`;
  });
  ctx.authLogs.filter((l) => l.accountId === ctx.alert.primaryAccountId).forEach((l) => {
    evidenceLabelMap[l.id] = `Auth Log ${l.id} (${l.eventType})`;
  });
  ctx.apiEvents.filter((e) => e.alertId === ctx.alert.id).forEach((e) => {
    evidenceLabelMap[e.id] = `API Event ${e.id} (${e.anomalyClass})`;
  });
  ctx.evidences.filter((e) => e.alertId === ctx.alert.id).forEach((e) => {
    evidenceLabelMap[e.id] = `Bằng chứng ${e.id} (${e.title})`;
  });
  ctx.devices.forEach((d) => {
    if (nodes.some((n) => n.id === d.id)) {
      evidenceLabelMap[d.id] = `Thiết bị ${d.id} (${d.osBrowser})`;
    }
  });

  const validEvidenceIds = Object.keys(evidenceLabelMap);
  const classification: CaseClassification =
    isSafeFp
      ? 'FALSE_POSITIVE_SAFE'
      : ctx.alert.scenarioCode === 'CYBER_ATO_MULE' || step3.status === 'CRITICAL'
        ? 'CONFIRMED_ATO_MULE'
        : ctx.alert.scenarioCode === 'BUSINESS_LOGIC_RACE' || step4.status === 'CRITICAL'
          ? 'CONFIRMED_LOGIC_ABUSE'
          : 'CONFIRMED_APP_SCAM';

  const recommendedActions: PlaybookActionItem[] =
    classification === 'FALSE_POSITIVE_SAFE'
      ? [
        {
          id: `ACT-SAFE-${ctx.alert.id}`,
          actionType: 'MARK_SAFE_FALSE_POSITIVE',
          labelVi: 'Đánh dấu Giao dịch An toàn — Không khóa oan tài khoản khách hàng',
          targetEntityId: ctx.alert.primaryAccountId,
          recommended: true,
        },
      ]
      : [
        {
          id: `ACT-SHIELD-${ctx.alert.id}`,
          actionType: 'ACTIVATE_COMMUNITY_SHIELD',
          labelVi: `Kích hoạt Lá chắn Ví Cộng đồng chặn tài khoản đích ${ctx.alert.targetRecipientAccountId}`,
          targetEntityId: ctx.alert.targetRecipientAccountId,
          recommended: true,
        },
        {
          id: `ACT-FREEZE-${ctx.alert.id}`,
          actionType:
            classification === 'CONFIRMED_LOGIC_ABUSE' ? 'ENFORCE_IDEMPOTENCY_LOCK' : 'FREEZE_MULE_ACCOUNTS',
          labelVi:
            classification === 'CONFIRMED_LOGIC_ABUSE'
              ? 'Khóa Idempotency Endpoint & Thu hồi số dư trục lợi Race Condition'
              : `Phong tỏa tạm thời tài khoản nghi vấn ${ctx.alert.targetRecipientAccountId}`,
          targetEntityId: ctx.alert.targetRecipientAccountId,
          recommended: true,
        },
      ];

  if (classification === 'CONFIRMED_ATO_MULE') {
    const flaggedDeviceId =
      ctx.authLogs.find(
        (l) =>
          l.accountId === ctx.alert.primaryAccountId &&
          (l.survivedCredentialReset || l.eventType === 'DEEPFAKE_VIRTUAL_CAM_INJECTION')
      )?.deviceId ??
      nodes.find((n) => n.nodeKind === 'SHARED_DEVICE')?.id ??
      null;

    recommendedActions.unshift({
      id: `ACT-REVOKE-${ctx.alert.id}`,
      actionType: 'REVOKE_TOKEN_FAMILY',
      labelVi: flaggedDeviceId
        ? `Thu hồi toàn bộ nhánh Refresh Token & khóa thiết bị nghi vấn ${flaggedDeviceId}`
        : 'Thu hồi toàn bộ nhánh Refresh Token & khóa thiết bị phát sinh phiên bất thường',
      targetEntityId: ctx.alert.primaryAccountId,
      recommended: true,
    });
  }

  const fallbackReport: InvestigationReport = {
    alertId: ctx.alert.id,
    classification,
    confidenceScore: isSafeFp ? 96 : 95,
    deterministicRiskScore,
    executiveSummaryVi: steps.map((s) => s.summaryVi).join(' '),
    keyFindingsVi: steps.map((s) => `${s.labelVi}: ${s.summaryVi}`),
    citedEvidenceIds: validEvidenceIds.slice(0, 6),
    toolTraceSteps: steps,
    recommendedActions,
    userShieldWarningVi: `CẢNH BÁO ĐỎ AEGIS SHIELD: Tài khoản nhận ${ctx.alert.targetRecipientAccountId} vừa bị phát hiện nằm trong đường dây lừa đảo/chiếm đoạt tài khoản. Giao dịch của bạn đã được chặn tự động để bảo vệ tài sản!`,
    modelUsed: 'deterministic-forensics-engine-v2',
    latencyMs: steps.reduce((sum, s) => sum + s.durationMs, 0),
    generatedAt: new Date().toISOString(),
  };

  return {
    alertId: ctx.alert.id,
    deterministicRiskScore,
    validEvidenceIds,
    evidenceLabelMap,
    toolTraceSteps: steps,
    riskAttributionFactors: combinedFactors,
    quantitativeMetrics: metrics,
    graphNodes: nodes,
    graphEdges: edges,
    urlThreatFindings,
    adaptiveFeedbackSummary: adaptiveResult.summary,
    fallbackReport,
  };
};
