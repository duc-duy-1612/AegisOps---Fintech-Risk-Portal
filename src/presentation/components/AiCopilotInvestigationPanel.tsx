'use client';

import { useEffect, useState } from 'react';
import {
  BarChart3,
  Bot,
  CheckCircle2,
  Clock,
  Cpu,
  ExternalLink,
  FileCheck2,
  Loader2,
  Lock,
  MessageSquare,
  RotateCcw,
  Send,
  ShieldCheck,
  Smartphone,
  Sparkles,
} from 'lucide-react';
import type {
  Account,
  AuditLogEntry,
  AuthSessionLog,
  CaseClassification,
  ClawbackReceiptRecord,
  DeviceFingerprint,
  ForensicSuiteOutput,
  FraudAlert,
  HitlFeedbackDecision,
  HitlFeedbackMemoryRecord,
  HitlFeedbackReasonCode,
  HitlFeedbackTargetScope,
  InvestigationReport,
  OperatorRole,
  Transaction,
} from '@/domain/types';
import {
  buildComplianceIncidentDossier,
  type ComplianceIncidentDossier,
} from '@/domain/compliance-report';
import { ComplianceReportModal } from './ComplianceReportModal';
import type { ChatMessageItem } from '@/presentation/hooks/useAegisWorkspace';

interface AiCopilotInvestigationPanelProps {
  alert: FraudAlert;
  forensics: ForensicSuiteOutput;
  report: InvestigationReport | null;
  accounts?: Account[];
  transactions?: Transaction[];
  authLogs?: AuthSessionLog[];
  devices?: DeviceFingerprint[];
  auditLogs?: AuditLogEntry[];
  operatorRole?: OperatorRole;
  isPendingL2Approval?: boolean;
  analystFeedbackCount?: number;
  clawbackReceipt?: ClawbackReceiptRecord | null;
  isInvestigating: boolean;
  isApprovingPlaybook: boolean;
  chatMessages: ChatMessageItem[];
  isAskingCopilot: boolean;
  onRunInvestigation: () => void;
  onApprovePlaybook: () => void;
  onClawbackRefund?: () => Promise<ClawbackReceiptRecord | null>;
  onAnalystOverride?: (params: {
    targetVerdict: 'OVERRIDE_SAFE' | 'FORCE_BLOCK';
    reasonVi: string;
  }) => Promise<boolean>;
  hitlFeedbackMemory?: HitlFeedbackMemoryRecord[];
  onCreateHitlFeedback?: (params: {
    alertId: string;
    feedbackDecision: HitlFeedbackDecision;
    targetScope?: HitlFeedbackTargetScope;
    reasonCode?: HitlFeedbackReasonCode;
    analystRationale: string;
    ttlHours?: number;
  }) => Promise<HitlFeedbackMemoryRecord | null>;
  onModerateHitlFeedback?: (params: {
    feedbackId: string;
    action: 'APPROVE' | 'REJECT' | 'REVOKE';
    rejectReasonVi?: string;
  }) => Promise<boolean>;
  onOpenWallet: () => void;
  onSelectCitation: (evidenceId: string) => void;
  onAskCopilot: (question: string) => void;
}

const LIVE_SCAN_STAGES = [
  '1/5 • Tính Z-Score hạn mức & đối chiếu KYC...',
  '2/5 • Truy vết đồ thị BFS, Smurfing Entropy & Mule Cluster...',
  '3/5 • Kiểm tra log xác thực ATO & Refresh Token Replay...',
  '4/5 • Quét xung đột Race Condition (TOCTOU) & chữ ký Webhook HMAC...',
  '5/5 • Gemini Multimodal đang đọc ảnh bằng chứng & tổng hợp Playbook...',
];

const SCENARIO_SUGGESTED_QUESTIONS: Record<FraudAlert['scenarioCode'], string[]> = {
  MULTIMODAL_APP_FRAUD: [
    'Vì sao khách đã quét FaceID theo QĐ 2345 mà AI vẫn phát hiện bị lừa đảo?',
    'Giải thích tín hiệu Đang nghe cuộc gọi lạ 19 phút + Paste STK từ Clipboard',
  ],
  CYBER_ATO_MULE: [
    'Tại sao phiên trên DEV-EMU-666 vẫn sống sau khi khách đã đổi mật khẩu?',
    'Chỉ số Smurfing Entropy = 0.99 của 3 lệnh 16M có ý nghĩa gì?',
  ],
  BUSINESS_LOGIC_RACE: [
    'Giải thích lỗ hổng Race Condition 12 req/140ms và cách khóa Idempotency?',
    'Tại sao callback thanh toán thiếu chữ ký HMAC lại nguy hiểm theo TT 50?',
  ],
  SMART_FALSE_POSITIVE: [
    'Tại sao AI giảm trừ 38 điểm rủi ro để không khóa oan khách hàng này?',
    'Cơ chế Trust Dampeners bảo vệ trải nghiệm người dùng như thế nào?',
  ],
  CUSTOM_SANDBOX: [
    'Tóm tắt các thực thể và dấu hiệu lừa đảo vừa bóc tách từ bằng chứng',
    'Soạn biên bản phong tỏa khẩn cấp tài khoản đích cho vụ việc này',
  ],
};

const CLASSIFICATION_LABELS: Record<
  CaseClassification,
  { titleVi: string; badgeColor: string }
> = {
  CONFIRMED_APP_SCAM: {
    titleVi: 'Xác nhận: Lừa đảo thao túng tâm lý (APP Fraud)',
    badgeColor: 'bg-red-500/20 text-red-200 border-red-500/40',
  },
  CONFIRMED_ATO_MULE: {
    titleVi: 'Xác nhận: Chiếm đoạt tài khoản & rửa tiền (ATO)',
    badgeColor: 'bg-red-500/20 text-red-200 border-red-500/40',
  },
  CONFIRMED_LOGIC_ABUSE: {
    titleVi: 'Xác nhận: Trục lợi lỗi hệ thống (Race Condition)',
    badgeColor: 'bg-amber-500/20 text-amber-200 border-amber-500/40',
  },
  FALSE_POSITIVE_SAFE: {
    titleVi: 'Giao dịch an toàn — Báo động giả (Không khóa oan)',
    badgeColor: 'bg-cyan-500/20 text-cyan-200 border-cyan-500/40',
  },
};

type CopilotSubTab = 'ATTRIBUTION' | 'TOOLS' | 'CHAT';

export const AiCopilotInvestigationPanel = ({
  alert,
  forensics,
  report,
  accounts = [],
  transactions = [],
  authLogs = [],
  devices = [],
  auditLogs = [],
  operatorRole = 'L2_CHECKER',
  isPendingL2Approval = false,
  analystFeedbackCount = 0,
  clawbackReceipt = null,
  isInvestigating,
  isApprovingPlaybook,
  chatMessages,
  isAskingCopilot,
  onRunInvestigation,
  onApprovePlaybook,
  onClawbackRefund,
  onAnalystOverride,
  hitlFeedbackMemory = [],
  onCreateHitlFeedback,
  onModerateHitlFeedback,
  onOpenWallet,
  onSelectCitation,
  onAskCopilot,
}: AiCopilotInvestigationPanelProps) => {
  const [questionInput, setQuestionInput] = useState('');
  const [subTab, setSubTab] = useState<CopilotSubTab>('ATTRIBUTION');
  const [scanStageIdx, setScanStageIdx] = useState(0);
  const [activeDossier, setActiveDossier] = useState<ComplianceIncidentDossier | null>(null);
  const [showOverridePanel, setShowOverridePanel] = useState(false);
  const [overrideReason, setOverrideReason] = useState('');
  const [feedbackScope, setFeedbackScope] = useState<HitlFeedbackTargetScope>('RECIPIENT_PATTERN');
  const [feedbackTtlHours, setFeedbackTtlHours] = useState<number>(24);
  const [isOverriding, setIsOverriding] = useState(false);
  const [moderatingId, setModeratingId] = useState<string | null>(null);
  const [isClawingBack, setIsClawingBack] = useState(false);

  useEffect(() => {
    if (!isInvestigating) {
      setScanStageIdx(0);
      return;
    }
    const timer = setInterval(() => {
      setScanStageIdx((prev) => (prev < LIVE_SCAN_STAGES.length - 1 ? prev + 1 : prev));
    }, 900);
    return () => clearInterval(timer);
  }, [isInvestigating]);

  const activeBrief = report ?? forensics.fallbackReport;
  const isResolved = alert.status === 'MITIGATED' || alert.status === 'DISMISSED_SAFE';
  const classInfo = CLASSIFICATION_LABELS[activeBrief.classification];
  const qMetrics = forensics.quantitativeMetrics;
  const eligibleSettledClawbackTxs = transactions.filter(
    (t) =>
      t.alertId === alert.id &&
      t.txKind !== 'CLAWBACK_REVERSAL' &&
      (t.status === 'COMPLETED' || t.status === 'SETTLED') &&
      t.senderAccountId === alert.primaryAccountId &&
      t.receiverAccountId === alert.targetRecipientAccountId
  );
  const eligibleSettledAmountVnd = eligibleSettledClawbackTxs.reduce(
    (sum, t) => sum + Math.round(t.amountVnd),
    0
  );
  const isAiUnavailableReport = Boolean(
    report && /unavailable|unconfigured/i.test(report.modelUsed)
  );
  const isDeterministicFallbackReport = Boolean(
    report && report.modelUsed.startsWith('deterministic-')
  );
  const isPartialReviewRequired = Boolean(
    report && !isDeterministicFallbackReport && !isAiUnavailableReport && report.citedEvidenceIds.length === 0
  );

  const handleOpenDossier = () => {
    const dossier = buildComplianceIncidentDossier({
      alert,
      forensics,
      report,
      auditLogs,
      accounts,
      transactions,
      authLogs,
      devices,
    });
    setActiveDossier(dossier);
  };

  return (
    <aside className="bg-slate-900/90 border border-slate-800 rounded-2xl p-4 flex flex-col gap-3 h-full min-h-0 overflow-y-auto shadow-lg">
      {/* Unified Header matching MoneyFlowGraphCanvas style */}
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Bot className="w-4 h-4 text-violet-400" />
          <h2 className="text-sm font-bold text-white">
            Trợ lý Điều tra AI &amp; Phản ứng Nhanh ({alert.id})
          </h2>
        </div>

        <button
          type="button"
          disabled={isInvestigating}
          onClick={onRunInvestigation}
          className={`cursor-pointer inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-bold transition-all shrink-0 ${!report && !isInvestigating
            ? 'bg-violet-600 hover:bg-violet-500 text-white shadow-sm'
            : 'bg-slate-950 hover:bg-slate-800 text-violet-200 border border-slate-700'
            }`}
        >
          {isInvestigating ? (
            <>
              <Loader2 className="w-3.5 h-3.5 animate-spin" />
              <span>Đang quét ({scanStageIdx + 1}/5)...</span>
            </>
          ) : (
            <>
              <Sparkles className="w-3.5 h-3.5 text-violet-300" />
              <span>{report ? 'Phân tích lại' : 'Bước 1: Chạy AI Điều tra'}</span>
            </>
          )}
        </button>
      </div>

      {/* Live 5-Stage Scanning Progress Bar */}
      {isInvestigating && (
        <div className="bg-violet-950/40 border border-violet-500/40 rounded-xl p-3 space-y-1.5">
          <div className="flex items-center justify-between text-xs font-bold text-violet-200">
            <span>{LIVE_SCAN_STAGES[scanStageIdx]}</span>
            <span>{Math.round(((scanStageIdx + 1) / 5) * 100)}%</span>
          </div>
          <div className="w-full h-1.5 bg-slate-900 rounded-full overflow-hidden">
            <div
              className="h-full bg-gradient-to-r from-violet-500 to-amber-400 transition-all duration-500"
              style={{ width: `${((scanStageIdx + 1) / 5) * 100}%` }}
            />
          </div>
        </div>
      )}

      {/* Primary Conclusion & 1-Click Action Card */}
      <div className="bg-slate-950 border border-slate-800 rounded-xl p-3.5 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <span className={`text-xs font-bold px-2.5 py-1 rounded-lg border ${classInfo.badgeColor}`}>
            {classInfo.titleVi}
          </span>
          <span className="text-xs font-semibold text-slate-300">
            Độ tin cậy: <strong className="text-amber-400">{activeBrief.confidenceScore}%</strong>
          </span>
        </div>

        {/* Explicit AI Source / Deterministic Fallback Provenance Badge (CR-2 & CR-2.1) */}
        <div
          data-testid="ai-source-badge"
          className={`flex flex-wrap items-center justify-between gap-1.5 px-2.5 py-1.5 rounded-lg border text-[11px] font-semibold ${!report
            ? 'bg-slate-900 border-slate-700 text-slate-300'
            : isAiUnavailableReport
              ? 'bg-red-950/50 border-red-500/40 text-red-200'
              : isDeterministicFallbackReport || isPartialReviewRequired
                ? 'bg-amber-950/50 border-amber-500/40 text-amber-200'
                : 'bg-violet-950/50 border-violet-500/40 text-violet-200'
            }`}
        >
          <span>
            {!report
              ? 'Nguồn: Tóm tắt Định lượng (Chưa gọi Live Gemini)'
              : isAiUnavailableReport
                ? `Nguồn: AI không khả dụng (${report.modelUsed} • Cần rà soát thủ công)`
                : isDeterministicFallbackReport
                  ? `Nguồn: Chế độ Dự phòng Định lượng (${report.modelUsed} • Gemini tạm không khả dụng)`
                  : isPartialReviewRequired
                    ? `Nguồn: Phân tích Live Gemini một phần (${report.modelUsed} • Thiếu mã trích dẫn, cần chuyên viên rà soát)`
                    : `Nguồn: Phân tích Live Gemini (${report.modelUsed} • Hỗ trợ điều tra, cần chuyên viên rà soát)`}
          </span>
          <span className="text-[10px] opacity-85">
            Quyết định gốc: Định lượng ({forensics.deterministicRiskScore}/100)
          </span>
        </div>

        <p className="text-xs text-slate-100 leading-relaxed">
          {activeBrief.executiveSummaryVi}
        </p>

        {/* Shadow Mode Benchmark Strip: Legacy Rule vs AegisOps Hybrid AI */}
        <div className="p-2.5 rounded-xl bg-slate-900/90 border border-slate-800 text-[11px] space-y-1">
          <div className="flex items-center justify-between gap-2 font-bold text-slate-300">
            <span>So sánh Đối chứng (Shadow Mode):</span>
            <span className="inline-flex items-center gap-1 text-amber-300">
              <Clock className="w-3 h-3" />
              Khung Giờ Vàng SLA &lt;180s
            </span>
          </div>
          <div className="text-slate-400">
            • <strong className="text-slate-200">Rule Cũ Truyền thống:</strong> {alert.traditionalRuleReason}
          </div>
          <div className="text-emerald-300">
            • <strong>AegisOps Hybrid AI:</strong> Chấm{' '}
            <strong>{forensics.deterministicRiskScore}/100</strong> ({classInfo.titleVi}) trong {activeBrief.latencyMs}ms.
          </div>
        </div>

        {/* Clickable Evidence Citation Chips */}
        <div>
          <div className="text-xs font-semibold text-slate-400 mb-1.5">
            Tham chiếu mã bằng chứng hợp lệ (kiểm định mã tồn tại — bấm để đối chiếu dữ liệu gốc bên trái):
          </div>
          <div className="flex flex-wrap gap-1.5">
            {activeBrief.citedEvidenceIds.map((evId) => (
              <button
                key={evId}
                type="button"
                onClick={() => onSelectCitation(evId)}
                className="cursor-pointer inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-xs font-bold bg-amber-500/15 hover:bg-amber-500/30 text-amber-300 border border-amber-500/40 transition-colors"
              >
                <span>{evId}</span>
                <ExternalLink className="w-3 h-3" />
              </button>
            ))}
          </div>
        </div>

        {/* Recommended SOP Playbook & Step 2 / Step 3 CTA */}
        <div className="pt-2.5 border-t border-slate-800 space-y-2">
          <div className="text-xs font-bold text-white flex items-center justify-between gap-2">
            <span>Hành động xử lý đề xuất (Kiểm soát kép Maker-Checker):</span>
            {isResolved ? (
              <span className="text-emerald-400 flex items-center gap-1 shrink-0">
                <CheckCircle2 className="w-3.5 h-3.5" /> Đã duyệt
              </span>
            ) : isPendingL2Approval ? (
              <span className="text-amber-300 bg-amber-500/15 px-2 py-0.5 rounded-md border border-amber-500/30 shrink-0">
                Chờ L2 phê duyệt
              </span>
            ) : null}
          </div>

          <div className="space-y-1.5">
            {activeBrief.recommendedActions.map((act) => (
              <div
                key={act.id}
                className="text-xs text-slate-100 bg-slate-900 px-3 py-2 rounded-lg border border-slate-800 flex items-start gap-2"
              >
                <ShieldCheck className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                <span className="leading-snug">{act.labelVi}</span>
              </div>
            ))}
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-12 gap-2 pt-1">
            {!isResolved ? (
              <button
                type="button"
                disabled={isApprovingPlaybook}
                onClick={onApprovePlaybook}
                className={`sm:col-span-8 cursor-pointer py-2.5 px-3 rounded-xl text-xs font-bold shadow-sm flex items-center justify-center gap-1.5 transition-colors ${operatorRole === 'L1_MAKER'
                  ? 'bg-cyan-500 hover:bg-cyan-400 text-slate-950'
                  : 'bg-amber-500 hover:bg-amber-400 text-slate-950'
                  }`}
              >
                {isApprovingPlaybook ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    <span>Đang xử lý...</span>
                  </>
                ) : operatorRole === 'L1_MAKER' ? (
                  <>
                    <Lock className="w-4 h-4" />
                    <span>
                      {isPendingL2Approval
                        ? 'Đã gửi L2 — Gửi nhắc lại L2 Checker'
                        : 'B3: Trình Playbook lên L2 (Maker)'}
                    </span>
                  </>
                ) : (
                  <>
                    <Lock className="w-4 h-4" />
                    <span>
                      {isPendingL2Approval
                        ? 'L2 Phê duyệt & Bật Lá chắn (Từ đề xuất L1)'
                        : 'Bước 2: Duyệt & Bật Lá chắn (1-Click)'}
                    </span>
                  </>
                )}
              </button>
            ) : (
              <button
                type="button"
                onClick={onOpenWallet}
                className="sm:col-span-8 cursor-pointer py-2.5 px-3 rounded-xl text-xs font-bold bg-emerald-500 hover:bg-emerald-400 text-slate-950 shadow-sm flex items-center justify-center gap-1.5 transition-colors"
              >
                <Smartphone className="w-4 h-4" />
                <span>Bước 3: Mở Ví Kiểm chứng Chặn Ngay</span>
              </button>
            )}

            <button
              type="button"
              onClick={handleOpenDossier}
              className="sm:col-span-4 cursor-pointer py-2.5 px-3 rounded-xl text-xs font-bold bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700 flex items-center justify-center gap-1.5 transition-colors"
            >
              <FileCheck2 className="w-3.5 h-3.5 text-cyan-400" />
              <span>Biên bản PDF</span>
            </button>
          </div>

          {/* 1-Click Golden-Window Clawback & Victim Refund Recovery (L2 Checker Only) */}
          {isResolved &&
            activeBrief.classification !== 'FALSE_POSITIVE_SAFE' &&
            onClawbackRefund &&
            operatorRole === 'L2_CHECKER' && (
              <div className="pt-1">
                {clawbackReceipt ? (
                  <div
                    className={`p-2.5 rounded-xl border text-xs flex items-center justify-between gap-2 ${clawbackReceipt.recoveryStatus === 'FAILED'
                      ? 'bg-red-950/60 border-red-500/50 text-red-100'
                      : clawbackReceipt.recoveryStatus === 'PARTIALLY_RECOVERED'
                        ? 'bg-amber-950/60 border-amber-500/50 text-amber-100'
                        : 'bg-emerald-950/60 border-emerald-500/50 text-emerald-100'
                      }`}
                  >
                    <div>
                      <div className="font-bold">
                        {clawbackReceipt.recoveryStatus === 'PARTIALLY_RECOVERED'
                          ? `Thu hồi một phần ${clawbackReceipt.recoveredAmountVnd.toLocaleString('vi-VN')} ₫ / ${(clawbackReceipt.requestedAmountVnd ?? clawbackReceipt.recoveredAmountVnd).toLocaleString('vi-VN')} ₫ (Thiếu ${(clawbackReceipt.missingAmountVnd ?? 0).toLocaleString('vi-VN')} ₫)`
                          : clawbackReceipt.recoveryStatus === 'FAILED'
                            ? 'Thu hồi thất bại: Tài khoản Mule không còn số dư khả dụng (0 ₫)'
                            : `Đã Thu hồi & Hoàn ${clawbackReceipt.recoveredAmountVnd.toLocaleString('vi-VN')} ₫ về Ví Nạn nhân`}
                      </div>
                      <div className="text-[11px] opacity-85">
                        Mã biên nhận: {clawbackReceipt.clawbackId}
                        {clawbackReceipt.reversalTxId ? ` • Đảo sổ: ${clawbackReceipt.reversalTxId}` : ''} • GD gốc: {clawbackReceipt.txIds.join(', ')}
                      </div>
                    </div>
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                  </div>
                ) : eligibleSettledClawbackTxs.length > 0 ? (
                  <button
                    type="button"
                    disabled={isClawingBack}
                    onClick={async () => {
                      setIsClawingBack(true);
                      try {
                        await onClawbackRefund();
                      } finally {
                        setIsClawingBack(false);
                      }
                    }}
                    className="cursor-pointer w-full py-2 px-3 rounded-xl bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-200 border border-cyan-500/40 font-bold text-xs flex items-center justify-center gap-1.5 transition-colors"
                  >
                    <RotateCcw className="w-3.5 h-3.5" />
                    <span>
                      {isClawingBack
                        ? 'Đang đảo sổ giao dịch đã hạch toán...'
                        : `Thu hồi & Hoàn trả GD Đã Hạch toán (${eligibleSettledClawbackTxs.map((t) => t.id).join(', ')} • ${eligibleSettledAmountVnd.toLocaleString('vi-VN')} ₫)`}
                    </span>
                  </button>
                ) : (
                  <div className="p-2.5 rounded-xl bg-slate-900 border border-slate-800 text-[11px] text-slate-300">
                    Không có giao dịch đã hạch toán (SETTLED/COMPLETED) đủ điều kiện thu hồi cho tài khoản nạn nhân chính. Các lệnh ở trạng thái HELD/BLOCKED không bị trừ tiền nên không phát sinh hoàn tiền Clawback.
                  </div>
                )}
              </div>
            )}

          {/* Human-in-the-Loop Analyst Override & Scoped Adaptive HITL Feedback Memory (L1 Propose / L2 Govern) */}
          {(onAnalystOverride || onCreateHitlFeedback) && operatorRole !== 'END_USER' && (
            <div className="pt-1.5 border-t border-slate-800/80 space-y-2">
              <div className="flex items-center justify-between gap-2 text-[11px]">
                <button
                  type="button"
                  onClick={() => setShowOverridePanel((v) => !v)}
                  className="cursor-pointer font-bold text-slate-300 hover:text-amber-300 underline decoration-slate-600"
                >
                  {showOverridePanel
                    ? 'Ẩn Bộ nhớ & Ghi đè HITL'
                    : `Bộ nhớ Phản hồi HITL & Ghi đè (${hitlFeedbackMemory.length})`}
                </button>
                <span className="text-slate-400">
                  Phản hồi dạy lại AI: <strong className="text-cyan-300">{analystFeedbackCount} lượt</strong>
                </span>
              </div>

              {showOverridePanel && (
                <div className="p-2.5 rounded-xl bg-slate-900 border border-slate-700 space-y-2.5 text-xs">
                  <div className="grid grid-cols-2 gap-2">
                    <div>
                      <label htmlFor="hitl-scope-select" className="block text-[10px] font-bold text-slate-400 mb-1">
                        Phạm vi tác động (Scoped)
                      </label>
                      <select
                        id="hitl-scope-select"
                        value={feedbackScope}
                        onChange={(e) => setFeedbackScope(e.target.value as HitlFeedbackTargetScope)}
                        className="w-full bg-slate-950 border border-slate-700 rounded-lg px-2 py-1 text-[11px] text-white font-semibold"
                      >
                        <option value="RECIPIENT_PATTERN">TK Nhận &amp; Ngữ cảnh này</option>
                        <option value="ALERT_CASE">Chỉ vụ việc {alert.id}</option>
                        <option value="TX_PATTERN">Mẫu giao dịch tương tự</option>
                      </select>
                    </div>
                    <div>
                      <label htmlFor="hitl-ttl-select" className="block text-[10px] font-bold text-slate-400 mb-1">
                        Thời hạn hiệu lực (TTL)
                      </label>
                      <select
                        id="hitl-ttl-select"
                        value={feedbackTtlHours}
                        onChange={(e) => setFeedbackTtlHours(Number(e.target.value))}
                        className="w-full bg-slate-950 border border-slate-700 rounded-lg px-2 py-1 text-[11px] text-white font-semibold"
                      >
                        <option value={24}>24 giờ (Khuyên dùng)</option>
                        <option value={72}>72 giờ</option>
                        <option value={1}>1 giờ (Tạm thời)</option>
                      </select>
                    </div>
                  </div>

                  <input
                    id="hitl-rationale-input"
                    type="text"
                    value={overrideReason}
                    onChange={(e) => setOverrideReason(e.target.value)}
                    placeholder="Nhập lý do phản hồi chuyên viên (lưu provenance & Audit Log)..."
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-1.5 text-white text-xs"
                  />

                  {/* Scoped Adaptive Feedback Buttons (L1 creates Pending, L2 creates Active) */}
                  {onCreateHitlFeedback && (
                    <div className="grid grid-cols-2 gap-2">
                      <button
                        type="button"
                        disabled={isOverriding}
                        onClick={async () => {
                          setIsOverriding(true);
                          try {
                            const created = await onCreateHitlFeedback({
                              alertId: alert.id,
                              feedbackDecision: 'OVERRIDE_SAFE',
                              targetScope: feedbackScope,
                              reasonCode: 'FALSE_POSITIVE_CONTEXT',
                              analystRationale: overrideReason,
                              ttlHours: feedbackTtlHours,
                            });
                            if (created) setOverrideReason('');
                          } finally {
                            setIsOverriding(false);
                          }
                        }}
                        className="cursor-pointer py-1.5 px-2 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-200 border border-cyan-500/40 font-bold text-[11px]"
                      >
                        {operatorRole === 'L1_MAKER' ? 'Đề xuất HITL An toàn' : 'Lưu Bộ nhớ HITL An toàn (-12đ)'}
                      </button>
                      <button
                        type="button"
                        disabled={isOverriding}
                        onClick={async () => {
                          setIsOverriding(true);
                          try {
                            const created = await onCreateHitlFeedback({
                              alertId: alert.id,
                              feedbackDecision: 'FORCE_BLOCK',
                              targetScope: feedbackScope,
                              reasonCode: 'CONFIRMED_MULE_PATTERN',
                              analystRationale: overrideReason,
                              ttlHours: feedbackTtlHours,
                            });
                            if (created) setOverrideReason('');
                          } finally {
                            setIsOverriding(false);
                          }
                        }}
                        className="cursor-pointer py-1.5 px-2 rounded-lg bg-amber-500/20 hover:bg-amber-500/30 text-amber-200 border border-amber-500/40 font-bold text-[11px]"
                      >
                        {operatorRole === 'L1_MAKER' ? 'Đề xuất HITL Cảnh giác' : 'Lưu Bộ nhớ HITL Rủi ro (+15đ)'}
                      </button>
                    </div>
                  )}

                  {/* Legacy Hard Override Action (L2 Checker Only) */}
                  {onAnalystOverride && operatorRole === 'L2_CHECKER' && (
                    <div className="grid grid-cols-2 gap-2 pt-1 border-t border-slate-800">
                      <button
                        type="button"
                        disabled={isOverriding}
                        onClick={async () => {
                          setIsOverriding(true);
                          try {
                            const ok = await onAnalystOverride({
                              targetVerdict: 'OVERRIDE_SAFE',
                              reasonVi: overrideReason,
                            });
                            if (ok) {
                              setShowOverridePanel(false);
                              setOverrideReason('');
                            }
                          } finally {
                            setIsOverriding(false);
                          }
                        }}
                        className="cursor-pointer py-1.5 px-2 rounded-lg bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-200 border border-emerald-500/40 font-bold text-[11px]"
                      >
                        Gỡ khóa oan (An toàn)
                      </button>
                      <button
                        type="button"
                        disabled={isOverriding}
                        onClick={async () => {
                          setIsOverriding(true);
                          try {
                            const ok = await onAnalystOverride({
                              targetVerdict: 'FORCE_BLOCK',
                              reasonVi: overrideReason,
                            });
                            if (ok) {
                              setShowOverridePanel(false);
                              setOverrideReason('');
                            }
                          } finally {
                            setIsOverriding(false);
                          }
                        }}
                        className="cursor-pointer py-1.5 px-2 rounded-lg bg-red-500/20 hover:bg-red-500/30 text-red-200 border border-red-500/40 font-bold text-[11px]"
                      >
                        Cưỡng chế Phong tỏa
                      </button>
                    </div>
                  )}

                  {/* Adaptive HITL Memory Audit List with Approve / Reject / Revoke Lifecycle */}
                  {hitlFeedbackMemory.length > 0 && (
                    <div className="pt-2 border-t border-slate-800 space-y-1.5 max-h-44 overflow-y-auto">
                      <div className="text-[11px] font-bold text-slate-300">
                        Lịch sử Bộ nhớ Phản hồi HITL trong phiên ({hitlFeedbackMemory.length}):
                      </div>
                      {hitlFeedbackMemory.map((rec) => (
                        <div
                          key={rec.feedbackId}
                          className="p-2 rounded-lg bg-slate-950 border border-slate-800 space-y-1 text-[11px]"
                        >
                          <div className="flex items-center justify-between gap-2 font-bold">
                            <span className="text-white truncate">
                              {rec.feedbackId} • {rec.feedbackDecision} ({rec.targetScope})
                            </span>
                            <span
                              className={`px-1.5 py-0.5 rounded text-[10px] shrink-0 ${rec.status === 'APPROVED_ACTIVE'
                                ? 'bg-emerald-500/20 text-emerald-300'
                                : rec.status === 'PENDING_APPROVAL'
                                  ? 'bg-amber-500/20 text-amber-300'
                                  : 'bg-slate-800 text-slate-400'
                                }`}
                            >
                              {rec.status}
                            </span>
                          </div>
                          <div className="text-slate-300">
                            Lý do: {rec.analystRationale} • Người tạo: <strong>{rec.actorPrincipalId}</strong> ({rec.actorRole}) • Điều chỉnh:{' '}
                            <strong>{rec.riskAdjustment > 0 ? `+${rec.riskAdjustment}đ` : `${rec.riskAdjustment}đ`}</strong>
                          </div>
                          {operatorRole === 'L2_CHECKER' && onModerateHitlFeedback && (
                            <div className="flex items-center gap-1.5 pt-0.5">
                              {rec.status === 'PENDING_APPROVAL' && (
                                <>
                                  <button
                                    type="button"
                                    disabled={moderatingId === rec.feedbackId}
                                    onClick={async () => {
                                      setModeratingId(rec.feedbackId);
                                      try {
                                        await onModerateHitlFeedback({
                                          feedbackId: rec.feedbackId,
                                          action: 'APPROVE',
                                        });
                                      } finally {
                                        setModeratingId(null);
                                      }
                                    }}
                                    className="cursor-pointer px-2 py-0.5 rounded bg-emerald-500/25 hover:bg-emerald-500/40 text-emerald-200 font-bold"
                                  >
                                    Duyệt (L2)
                                  </button>
                                  <button
                                    type="button"
                                    disabled={moderatingId === rec.feedbackId}
                                    onClick={async () => {
                                      setModeratingId(rec.feedbackId);
                                      try {
                                        await onModerateHitlFeedback({
                                          feedbackId: rec.feedbackId,
                                          action: 'REJECT',
                                        });
                                      } finally {
                                        setModeratingId(null);
                                      }
                                    }}
                                    className="cursor-pointer px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 font-bold"
                                  >
                                    Từ chối
                                  </button>
                                </>
                              )}
                              {rec.status === 'APPROVED_ACTIVE' && (
                                <button
                                  type="button"
                                  disabled={moderatingId === rec.feedbackId}
                                  onClick={async () => {
                                    setModeratingId(rec.feedbackId);
                                    try {
                                      await onModerateHitlFeedback({
                                        feedbackId: rec.feedbackId,
                                        action: 'REVOKE',
                                      });
                                    } finally {
                                      setModeratingId(null);
                                    }
                                  }}
                                  className="cursor-pointer px-2 py-0.5 rounded bg-red-500/20 hover:bg-red-500/35 text-red-200 font-bold"
                                >
                                  Thu hồi (Revoke)
                                </button>
                              )}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Clean 3-Tab Sub-Panel (Eliminates vertical box stacking!) */}
      <div className="bg-slate-950 border border-slate-800 rounded-xl p-3.5 flex flex-col gap-3 flex-1">
        <div className="flex flex-wrap items-center gap-1.5 border-b border-slate-800 pb-2">
          <button
            type="button"
            onClick={() => setSubTab('ATTRIBUTION')}
            className={`cursor-pointer px-2.5 py-1 rounded-lg text-xs font-bold flex items-center gap-1.5 transition-colors ${subTab === 'ATTRIBUTION'
              ? 'bg-amber-500 text-slate-950'
              : 'bg-slate-900 text-slate-300 hover:text-white border border-slate-800'
              }`}
          >
            <BarChart3 className="w-3.5 h-3.5" />
            <span>Trọng số Rủi ro ({forensics.deterministicRiskScore}/100)</span>
          </button>

          <button
            type="button"
            onClick={() => setSubTab('TOOLS')}
            className={`cursor-pointer px-2.5 py-1 rounded-lg text-xs font-bold flex items-center gap-1.5 transition-colors ${subTab === 'TOOLS'
              ? 'bg-amber-500 text-slate-950'
              : 'bg-slate-900 text-slate-300 hover:text-white border border-slate-800'
              }`}
          >
            <Cpu className="w-3.5 h-3.5" />
            <span>5 Công cụ Kiểm tra</span>
          </button>

          <button
            type="button"
            onClick={() => setSubTab('CHAT')}
            className={`cursor-pointer px-2.5 py-1 rounded-lg text-xs font-bold flex items-center gap-1.5 transition-colors ${subTab === 'CHAT'
              ? 'bg-violet-500 text-white'
              : 'bg-slate-900 text-slate-300 hover:text-white border border-slate-800'
              }`}
          >
            <MessageSquare className="w-3.5 h-3.5" />
            <span>Hỏi đáp AI Copilot</span>
          </button>
        </div>

        {/* Sub-Tab 1: Quantitative Metrics & SHAP-like Risk Attribution */}
        {subTab === 'ATTRIBUTION' && (
          <div className="space-y-2.5">
            <div className="grid grid-cols-4 gap-1.5 bg-slate-900 p-2 rounded-lg border border-slate-800 text-center">
              <div>
                <div className="text-[11px] text-slate-400">Z-Score</div>
                <div className="text-xs font-bold text-amber-300">
                  {qMetrics.zScoreDeviation >= 0 ? `+${qMetrics.zScoreDeviation}` : qMetrics.zScoreDeviation}σ
                </div>
              </div>
              <div>
                <div className="text-[11px] text-slate-400">Smurfing</div>
                <div className="text-xs font-bold text-cyan-300">{qMetrics.smurfingEntropyIndex}</div>
              </div>
              <div>
                <div className="text-[11px] text-slate-400">Mule Cluster</div>
                <div className="text-xs font-bold text-rose-300">{qMetrics.deviceBipartiteClusterScore}</div>
              </div>
              <div>
                <div className="text-[11px] text-slate-400">Fan-In</div>
                <div className="text-xs font-bold text-violet-300">{qMetrics.crossVictimFanIn} KH</div>
              </div>
            </div>

            {forensics.adaptiveFeedbackSummary &&
              (forensics.adaptiveFeedbackSummary.appliedRecords.length > 0 ||
                forensics.adaptiveFeedbackSummary.conflictDetected ||
                forensics.adaptiveFeedbackSummary.hardRuleBlockedOverride) && (
                <div className="p-2 rounded-lg bg-slate-900 border border-cyan-500/40 space-y-1 text-[11px]">
                  {forensics.adaptiveFeedbackSummary.conflictDetected && (
                    <div className="text-amber-300 font-bold">
                      ⚠ {forensics.adaptiveFeedbackSummary.needsReviewVi}
                    </div>
                  )}
                  {forensics.adaptiveFeedbackSummary.hardRuleBlockedOverride && (
                    <div className="text-rose-300 font-bold">
                      🛡 {forensics.adaptiveFeedbackSummary.hardRuleNoticeVi}
                    </div>
                  )}
                  {forensics.adaptiveFeedbackSummary.appliedRecords.length > 0 && (
                    <div className="text-cyan-200 font-semibold">
                      Adaptive HITL Memory: Điểm gốc{' '}
                      <strong>{forensics.adaptiveFeedbackSummary.baseScoreBeforeFeedback}</strong> → Sau điều chỉnh{' '}
                      <strong>{forensics.adaptiveFeedbackSummary.finalScoreAfterFeedback}</strong>
                    </div>
                  )}
                </div>
              )}

            <div className="space-y-1.5">
              {forensics.riskAttributionFactors.map((fac) => (
                <div
                  key={fac.id}
                  className="flex items-center justify-between gap-2 text-xs px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-800"
                >
                  <span className="text-slate-200 leading-snug">{fac.labelVi}</span>
                  <span
                    className={`font-bold px-2 py-0.5 rounded-md shrink-0 ${fac.kind === 'TRUST_DAMPENER' || fac.kind === 'ADAPTIVE_HITL_DAMPENER'
                      ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                      : 'bg-red-500/20 text-red-300 border border-red-500/30'
                      }`}
                  >
                    {fac.deltaScore > 0 ? `+${fac.deltaScore}đ` : `${fac.deltaScore}đ`}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Sub-Tab 2: 5 Deterministic Forensics Tools */}
        {subTab === 'TOOLS' && (
          <div className="space-y-2 max-h-56 overflow-y-auto pr-1">
            {forensics.toolTraceSteps.map((step) => (
              <div
                key={step.toolName}
                className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 text-xs"
              >
                <div className="flex items-center justify-between gap-2 mb-1">
                  <span className="text-white font-bold">{step.labelVi}</span>
                  <span
                    className={`px-2 py-0.5 rounded-md text-[11px] font-bold shrink-0 ${step.status === 'CRITICAL'
                      ? 'bg-red-500/20 text-red-300'
                      : step.status === 'WARNING'
                        ? 'bg-amber-500/20 text-amber-300'
                        : 'bg-emerald-500/20 text-emerald-300'
                      }`}
                  >
                    {step.status === 'CRITICAL'
                      ? 'Nguy cơ cao'
                      : step.status === 'WARNING'
                        ? 'Cảnh báo'
                        : 'Bình thường'}
                  </span>
                </div>
                <p className="text-slate-300 leading-relaxed">{step.summaryVi}</p>
              </div>
            ))}
          </div>
        )}

        {/* Sub-Tab 3: Copilot Q&A Chat */}
        {subTab === 'CHAT' && (
          <div className="flex flex-col gap-2.5 flex-1">
            <div className="space-y-2 max-h-44 overflow-y-auto pr-1 text-xs">
              {chatMessages.length === 0 ? (
                <div className="flex flex-col gap-1.5">
                  <span className="text-slate-400">Chọn câu hỏi gợi ý hoặc nhập câu hỏi bên dưới:</span>
                  {(SCENARIO_SUGGESTED_QUESTIONS[alert.scenarioCode] ?? []).map((q) => (
                    <button
                      key={q}
                      type="button"
                      onClick={() => onAskCopilot(q)}
                      className="cursor-pointer text-left text-xs px-3 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-800 transition-colors"
                    >
                      &ldquo;{q}&rdquo;
                    </button>
                  ))}
                </div>
              ) : (
                chatMessages.map((m) => (
                  <div
                    key={m.id}
                    className={`p-2.5 rounded-lg text-xs leading-relaxed ${m.role === 'analyst'
                      ? 'bg-violet-600/20 text-violet-100 border border-violet-500/30'
                      : 'bg-slate-900 text-slate-100 border border-slate-800'
                      }`}
                  >
                    <p>{m.text}</p>
                  </div>
                ))
              )}
            </div>

            <form
              onSubmit={(e) => {
                e.preventDefault();
                if (!questionInput.trim() || isAskingCopilot) return;
                onAskCopilot(questionInput);
                setQuestionInput('');
              }}
              className="flex items-center gap-2 mt-auto"
            >
              <input
                type="text"
                value={questionInput}
                onChange={(e) => setQuestionInput(e.target.value)}
                placeholder="Nhập câu hỏi cho AI Copilot..."
                className="flex-1 bg-slate-900 border border-slate-700 rounded-xl px-3 py-2 text-xs text-white placeholder:text-slate-400 focus:outline-none focus:border-violet-400"
              />
              <button
                type="submit"
                disabled={isAskingCopilot}
                aria-label="Gửi câu hỏi Copilot"
                className="cursor-pointer px-3 py-2 rounded-xl bg-violet-600 hover:bg-violet-500 text-white text-xs font-bold"
              >
                {isAskingCopilot ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
              </button>
            </form>
          </div>
        )}
      </div>

      <ComplianceReportModal
        dossier={activeDossier}
        onClose={() => setActiveDossier(null)}
      />
    </aside >
  );
};
