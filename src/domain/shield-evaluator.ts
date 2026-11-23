import { resolveEffectiveFeedbackStatus } from './hitl-feedback-engine';
import type {
  Account,
  ConsumerTransferDecision,
  ConsumerTransferRequest,
  HitlFeedbackMemoryRecord,
  PsychologicalDeEscalationCard,
  RecipientTrustStatus,
  ShieldRule,
} from './types';

const HIGH_RISK_TRANSFER_NOTES = [
  'xac minh tai san',
  'xác minh tài sản',
  'tam giu',
  'tạm giữ',
  'cong an',
  'công an',
  'hoan tien',
  'hoàn tiền',
  'phikichhoat',
  'nang cap sim',
  'nhiem vu',
  'nhiệm vụ',
  'chuyen nham',
  'chuyển nhầm',
];

const buildDeEscalationCard = (
  message: string,
  recipientName: string
): PsychologicalDeEscalationCard => {
  const lower = message.toLowerCase();
  if (lower.includes('shipper') || lower.includes('hoan tien') || lower.includes('hoàn tiền')) {
    return {
      archetypeTitleVi: 'Kịch bản: Giả danh Shipper / CSKH gửi link hoàn tiền',
      manipulationTacticVi:
        'Kẻ gian lợi dụng tâm lý sợ mất tiền cọc hoặc bị trừ phí hội viên hàng tháng để ép bạn bấm link lạ và chuyển tiền "xác thực hoàn tiền".',
      realityChecklistVi: [
        'Không có đơn vị vận chuyển nào yêu cầu khách chuyển khoản đi để được nhận tiền hoàn.',
        'Tuyệt đối KHÔNG chuyển tiền sang ngân hàng/ví khác cho đối tượng này.',
        'Kiểm tra tình trạng đơn hàng trực tiếp trên ứng dụng mua sắm chính thức.',
      ],
      emergencyHotlineVi: 'Đường dây nóng An ninh MoMo: 1900 5454 41 (Nhánh Khẩn cấp)',
    };
  }

  return {
    archetypeTitleVi: `Kịch bản: Thao túng tâm lý chuyển tiền vào TK Rác (${recipientName})`,
    manipulationTacticVi:
      'Kẻ gian tạo áp lực sợ hãi khẩn cấp (dọa khóa tài khoản, lệnh bắt giữ giả, hoặc cam kết trả thưởng trong 15 phút) và yêu cầu bạn GIỮ BÍ MẬT với người thân.',
    realityChecklistVi: [
      'Cơ quan Công an, Viện kiểm sát, Ngân hàng KHÔNG làm việc qua Zalo/Điện thoại và KHÔNG có "Tài khoản tạm giữ xác minh tài sản".',
      'Không mở ứng dụng ngân hàng khác để cố chuyển lại khoản tiền này.',
      'Hãy gọi ngay cho người thân trong gia đình hoặc công an phường gần nhất để kiểm chứng.',
    ],
    emergencyHotlineVi: 'Đường dây nóng An ninh MoMo & Cảnh báo C05: 1900 5454 41',
  };
};

export const evaluateConsumerTransfer = (
  request: ConsumerTransferRequest,
  activeShieldRules: ShieldRule[],
  accounts: Account[],
  options?: {
    hitlFeedbackMemory?: HitlFeedbackMemoryRecord[];
    targetFingerprintsByAccountId?: Record<string, string>;
    legacyTargetFingerprintsByAccountId?: Record<string, string[]>;
    nowMs?: number;
  }
): ConsumerTransferDecision => {
  const start = performance.now();
  const normalizedTarget = request.recipientAccountIdOrNumber.trim().toUpperCase();

  const targetAccount = accounts.find(
    (a) =>
      a.id.toUpperCase() === normalizedTarget ||
      a.accountNumber.toUpperCase() === normalizedTarget
  );

  // 1. Check active Community Shield Rules (Closed-Loop Protection)
  const matchedRule = activeShieldRules.find(
    (rule) =>
      rule.active &&
      (rule.targetAccountId.toUpperCase() === normalizedTarget ||
        rule.targetAccountNumber.toUpperCase() === normalizedTarget ||
        (targetAccount &&
          (rule.targetAccountId === targetAccount.id ||
            rule.targetAccountNumber === targetAccount.accountNumber)))
  );

  const elapsedMs = Math.max(1, Math.round(performance.now() - start));

  if (matchedRule) {
    return {
      decision: 'BLOCKED_BY_SHIELD',
      matchedRuleId: matchedRule.id,
      recipientAccountNumber: matchedRule.targetAccountNumber,
      recipientName: matchedRule.targetOwnerName,
      amountVnd: request.amountVnd,
      titleVi: 'GIAO DỊCH ĐÃ ĐƯỢC CHẶN BỞI LÁ CHẮN AEGIS SHIELD',
      explanationVi: matchedRule.userWarningVi,
      coolingOffQuestionsVi: [
        'Tài khoản nhận này vừa bị đội ngũ An ninh Fintech phong tỏa do liên quan trực tiếp đến đường dây lừa đảo/chiếm đoạt tài khoản.',
        'Cơ quan Công an, Viện kiểm sát hoặc Shipper KHÔNG BAO GIỜ yêu cầu chuyển tiền để "xác minh tài sản" hay "kích hoạt hoàn tiền".',
        `Số tiền ${request.amountVnd.toLocaleString('vi-VN')} ₫ của bạn vẫn an toàn 100% trong ví.`,
      ],
      deEscalationCardVi: buildDeEscalationCard(request.message, matchedRule.targetOwnerName),
      responseTimeMs: elapsedMs,
    };
  }

  // 2. Check if recipient account is already FROZEN in ledger
  if (targetAccount && targetAccount.status === 'FROZEN') {
    return {
      decision: 'BLOCKED_BY_SHIELD',
      matchedRuleId: 'LEDGER-FROZEN-GUARD',
      recipientAccountNumber: targetAccount.accountNumber,
      recipientName: targetAccount.ownerName,
      amountVnd: request.amountVnd,
      titleVi: 'TÀI KHOẢN NHẬN ĐÃ BỊ PHONG TỎA KHẨN CẤP',
      explanationVi: `Tài khoản ${targetAccount.accountNumber} (${targetAccount.ownerName}) đang bị khóa nhận tiền để điều tra gian lận. Giao dịch ${request.amountVnd.toLocaleString('vi-VN')} ₫ đã được chặn an toàn.`,
      coolingOffQuestionsVi: [
        'Không thực hiện chuyển tiền sang số tài khoản khác theo lời hướng dẫn của đối tượng.',
      ],
      deEscalationCardVi: buildDeEscalationCard(request.message, targetAccount.ownerName),
      responseTimeMs: elapsedMs,
    };
  }

  // 3. Heuristic Cooling-Off check if note contains social engineering phrases before Ops even approves
  const lowerMsg = request.message.toLowerCase();
  const hasScamNote = HIGH_RISK_TRANSFER_NOTES.some((phrase) => lowerMsg.includes(phrase));
  if (hasScamNote) {
    return {
      decision: 'WARN_COOLING_OFF',
      recipientAccountNumber: targetAccount?.accountNumber ?? normalizedTarget,
      recipientName: targetAccount?.ownerName ?? 'Tài khoản chưa xác thực lá chắn',
      amountVnd: request.amountVnd,
      titleVi: 'CẢNH BÁO LÀM NGUỘI TÂM LÝ (SMART COOLING-OFF)',
      explanationVi:
        'Nội dung chuyển khoản có dấu hiệu của kịch bản thao túng tâm lý. Đội ngũ AegisOps chưa bật lệnh chặn cứng trên tài khoản này — bạn có thể bấm "Báo cáo Nghi lừa đảo lên AegisOps" hoặc bấm Bước 2 Duyệt Playbook trên Workspace!',
      coolingOffQuestionsVi: [
        'Bạn có đang bị ai đó thúc giục chuyển tiền qua điện thoại hoặc Zalo không?',
        'Hãy bấm nút "Báo cáo Khẩn cấp lên Đội ngũ AegisOps" bên dưới hoặc duyệt Playbook trên Workspace.',
      ],
      deEscalationCardVi: buildDeEscalationCard(
        request.message,
        targetAccount?.ownerName ?? normalizedTarget
      ),
      responseTimeMs: elapsedMs,
    };
  }

  // 4. Scoped Adaptive HITL Memory check (Active, non-expired FORCE_BLOCK adds protective Cooling-Off warning; SAFE never bypasses hard rules above)
  const hitlMemory = options?.hitlFeedbackMemory ?? [];
  if (hitlMemory.length > 0 && targetAccount) {
    const nowMs = options?.nowMs ?? Date.now();
    const fp = options?.targetFingerprintsByAccountId?.[targetAccount.id] ?? targetAccount.id;
    const legacyFps = options?.legacyTargetFingerprintsByAccountId?.[targetAccount.id] ?? [];
    const matchingActive = hitlMemory.filter((rec) => {
      if (resolveEffectiveFeedbackStatus(rec, nowMs) !== 'APPROVED_ACTIVE') return false;
      if (rec.targetScope === 'ALERT_CASE') return false;
      return (
        rec.recipientAccountId === targetAccount.id ||
        rec.targetFingerprint === fp ||
        legacyFps.includes(rec.targetFingerprint)
      );
    });
    const hasSafe = matchingActive.some((r) => r.feedbackDecision === 'OVERRIDE_SAFE');
    const blockMatch = matchingActive.find((r) => r.feedbackDecision === 'FORCE_BLOCK');
    if (blockMatch) {
      if (hasSafe) {
        return {
          decision: 'WARN_COOLING_OFF',
          recipientAccountNumber: targetAccount.accountNumber,
          recipientName: targetAccount.ownerName,
          amountVnd: request.amountVnd,
          titleVi: 'CẢNH BÁO XUNG ĐỘT BỘ NHỚ PHẢN HỒI CHUYÊN VIÊN (NEEDS REVIEW)',
          explanationVi: `Phát hiện xung đột phản hồi HITL đang hoạt động (SAFE vs FORCE_BLOCK • ${blockMatch.feedbackId}) cho tài khoản ${targetAccount.accountNumber}. Hệ thống ưu tiên an toàn, tạm giữ để xác minh thủ công thay vì tự động cho qua.`,
          coolingOffQuestionsVi: [
            'Tài khoản nhận đang có đánh giá xung đột giữa các chuyên viên vận hành.',
            'Vui lòng xác minh lại danh tính người nhận trước khi thực hiện giao dịch.',
          ],
          deEscalationCardVi: buildDeEscalationCard(request.message, targetAccount.ownerName),
          responseTimeMs: elapsedMs,
        };
      }
      return {
        decision: 'WARN_COOLING_OFF',
        recipientAccountNumber: targetAccount.accountNumber,
        recipientName: targetAccount.ownerName,
        amountVnd: request.amountVnd,
        titleVi: 'CẢNH BÁO TỪ BỘ NHỚ PHẢN HỒI CHUYÊN VIÊN (ADAPTIVE HITL MEMORY)',
        explanationVi: `Chuyên viên L2 đã gắn cờ rủi ro có thời hạn (${blockMatch.feedbackId} • Hết hạn ${new Date(blockMatch.expiresAt).toLocaleString('vi-VN')}): ${blockMatch.analystRationale}`,
        coolingOffQuestionsVi: [
          'Tài khoản nhận này đang nằm trong vùng theo dõi Adaptive HITL Memory.',
          'Vui lòng xác minh lại danh tính người nhận trước khi xác nhận chuyển tiền.',
        ],
        deEscalationCardVi: buildDeEscalationCard(request.message, targetAccount.ownerName),
        responseTimeMs: elapsedMs,
      };
    }
  }

  return {
    decision: 'ALLOWED_SAFE',
    recipientAccountNumber: targetAccount?.accountNumber ?? normalizedTarget,
    recipientName: targetAccount?.ownerName ?? 'Người nhận hợp lệ',
    amountVnd: request.amountVnd,
    titleVi: 'GIAO DỊCH HỢP LỆ — KHÔNG CÓ CẢNH BÁO RỦI RO',
    explanationVi: `Tài khoản nhận ${targetAccount?.accountNumber ?? normalizedTarget} hiện không nằm trong danh sách chặn của Aegis Shield.`,
    coolingOffQuestionsVi: [],
    responseTimeMs: elapsedMs,
  };
};

/**
 * Real-Time 3-Color Trust Traffic Light (MoMo + A05/C05/SIMO Standard)
 * Evaluates beneficiary trustworthiness BEFORE the user presses transfer.
 */
export const evaluateRecipientTrustTrafficLight = (
  recipientAccountIdOrNumber: string,
  activeShieldRules: ShieldRule[],
  accounts: Account[]
): RecipientTrustStatus => {
  const normalizedTarget = recipientAccountIdOrNumber.trim().toUpperCase();
  if (!normalizedTarget) {
    return {
      color: 'YELLOW',
      badgeVi: 'CHƯA XÁC ĐỊNH',
      headlineVi: 'Nhập số tài khoản để kiểm tra độ tin cậy Aegis Shield',
      detailVi: 'Hệ thống sẽ đối chiếu danh sách cảnh báo A05/SIMO và AegisOps theo thời gian thực.',
      sourceTag: 'Aegis Trust Engine',
    };
  }

  const targetAccount = accounts.find(
    (a) =>
      a.id.toUpperCase() === normalizedTarget ||
      a.accountNumber.toUpperCase() === normalizedTarget
  );

  const matchedRule = activeShieldRules.find(
    (rule) =>
      rule.active &&
      (rule.targetAccountId.toUpperCase() === normalizedTarget ||
        rule.targetAccountNumber.toUpperCase() === normalizedTarget ||
        (targetAccount &&
          (rule.targetAccountId === targetAccount.id ||
            rule.targetAccountNumber === targetAccount.accountNumber)))
  );

  if (matchedRule || targetAccount?.status === 'FROZEN') {
    return {
      color: 'RED',
      badgeVi: 'ĐỎ • NGUY CƠ LỪA ĐẢO CAO',
      headlineVi: `Cảnh báo Đỏ: Tài khoản ${targetAccount?.accountNumber ?? normalizedTarget} thuộc danh sách chặn Aegis Shield`,
      detailVi:
        'Đã xác nhận liên quan đường dây lừa đảo / chiếm đoạt tài khoản. Mọi lệnh chuyển tiền sẽ bị chặn tự động.',
      sourceTag: 'Aegis Shield • SIMO / A05',
    };
  }

  if (targetAccount?.accountType === 'TRUSTED_INSTITUTION') {
    return {
      color: 'GREEN',
      badgeVi: 'XANH LÁ • AN TOÀN ĐÃ XÁC THỰC',
      headlineVi: `${targetAccount.ownerName} — Đối tác y tế / doanh nghiệp uy tín`,
      detailVi: `Tài khoản hoạt động ổn định ${targetAccount.accountAgeDays} ngày, khớp 100% tên đăng ký NAPAS.`,
      sourceTag: 'NAPAS Verified Partner',
    };
  }

  if (targetAccount?.accountType === 'MULE_SUSPECT' || (targetAccount && targetAccount.accountAgeDays < 30)) {
    return {
      color: 'YELLOW',
      badgeVi: 'VÀNG • TIỀM ẨN RỦI RO',
      headlineVi: `Cảnh giác: Tài khoản mới mở (${targetAccount.accountAgeDays} ngày, KYC ${targetAccount.kycLevel})`,
      detailVi:
        'Chưa bị khóa cứng nhưng có dấu hiệu tài khoản trung gian (Mule). Hãy duyệt Playbook ở Workspace để nâng lên Đèn Đỏ.',
      sourceTag: 'Aegis Early Warning',
    };
  }

  if (!targetAccount) {
    return {
      color: 'YELLOW',
      badgeVi: 'VÀNG • TÀI KHOẢN LẠ NGOÀI DANH BẠ',
      headlineVi: `Số tài khoản ${normalizedTarget} chưa có lịch sử giao dịch an toàn`,
      detailVi: 'Kiểm tra kỹ tên người nhận trước khi xác nhận chuyển tiền.',
      sourceTag: 'Aegis Trust Engine',
    };
  }

  return {
    color: 'GREEN',
    badgeVi: 'XANH LÁ • CHƯA GHI NHẬN RỦI RO',
    headlineVi: `${targetAccount.ownerName} — Tài khoản hoạt động bình thường`,
    detailVi: `Thâm niên ${targetAccount.accountAgeDays} ngày, chưa có phản ánh lừa đảo.`,
    sourceTag: 'Aegis Trust Engine',
  };
};
