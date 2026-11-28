'use client';

import { useRef, useState } from 'react';
import {
  ArrowRight,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Clock,
  Download,
  FilePlus2,
  FileSpreadsheet,
  Layers,
  Lock,
  Play,
  Radio,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  Smartphone,
  Upload,
  UserCheck,
} from 'lucide-react';
import { exportCasesToCsv, generateSampleBatchCsv } from '@/domain/batch-io';
import { computeDashboardKpiMetrics } from '@/domain/dashboard-kpis';
import type {
  Account,
  AuditLogEntry,
  ClawbackReceiptRecord,
  ForensicSuiteOutput,
  FraudAlert,
  InvestigationReport,
  ShieldRule,
  Transaction,
} from '@/domain/types';
import type { WorkspaceViewId } from './AppShellSidebar';
import type { CaseTagFilterId, TagFilterOption } from './WorkspaceCommandHeader';

interface OverviewDashboardViewProps {
  alerts: FraudAlert[];
  allAlertsCount: number;
  accounts: Account[];
  forensicsMap: Record<string, ForensicSuiteOutput>;
  activeShieldRules: ShieldRule[];
  pendingL2ApprovalAlertIds?: string[];
  auditLogs: AuditLogEntry[];
  clawbackReceipts?: ClawbackReceiptRecord[];
  transactions?: Transaction[];
  reportsByAlertId?: Record<string, InvestigationReport>;
  falsePositivesSaved: number;
  mitigatedCount: number;
  selfRescuedAmountVnd?: number;
  isImportingBatch?: boolean;
  isLiveFeedEnabled?: boolean;
  selectedTagFilter?: CaseTagFilterId;
  tagOptions?: TagFilterOption[];
  onSelectTagFilter?: (tag: CaseTagFilterId) => void;
  onOpenAlertInvestigation: (alertId: string) => void;
  onEditAlertSpec: (alertId: string) => void;
  onNavigateView: (view: WorkspaceViewId) => void;
  onRunAutoDemo: () => void;
  onImportBatchFile?: (rawContent: string, fileName: string) => Promise<boolean>;
  onToggleLiveFeed?: () => void;
}

const SCENARIO_TAG_META: Record<
  FraudAlert['scenarioCode'],
  { labelVi: string; pillClass: string }
> = {
  MULTIMODAL_APP_FRAUD: {
    labelVi: 'Lừa đảo APP Fraud',
    pillClass: 'bg-amber-500/10 text-amber-300 border-amber-500/25',
  },
  CYBER_ATO_MULE: {
    labelVi: 'Chiếm đoạt ATO',
    pillClass: 'bg-red-500/10 text-red-300 border-red-500/25',
  },
  BUSINESS_LOGIC_RACE: {
    labelVi: 'Lỗi API Race',
    pillClass: 'bg-violet-500/10 text-violet-300 border-violet-500/25',
  },
  SMART_FALSE_POSITIVE: {
    labelVi: 'Tránh khóa oan',
    pillClass: 'bg-cyan-500/10 text-cyan-300 border-cyan-500/25',
  },
  CUSTOM_SANDBOX: {
    labelVi: 'Hồ sơ Tự tạo',
    pillClass: 'bg-emerald-500/10 text-emerald-300 border-emerald-500/25',
  },
};

export const OverviewDashboardView = ({
  alerts,
  allAlertsCount,
  accounts,
  forensicsMap,
  activeShieldRules,
  pendingL2ApprovalAlertIds = [],
  auditLogs,
  clawbackReceipts = [],
  transactions = [],
  reportsByAlertId = {},
  falsePositivesSaved,
  mitigatedCount: _mitigatedCount,
  selfRescuedAmountVnd = 0,
  isImportingBatch = false,
  isLiveFeedEnabled = false,
  selectedTagFilter = 'ALL',
  tagOptions = [],
  onSelectTagFilter,
  onOpenAlertInvestigation,
  onEditAlertSpec,
  onNavigateView,
  onRunAutoDemo,
  onImportBatchFile,
  onToggleLiveFeed,
}: OverviewDashboardViewProps) => {
  void _mitigatedCount;
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const [showDetailsPanel, setShowDetailsPanel] = useState(false);
  const [detailsTab, setDetailsTab] = useState<'SHADOW' | 'ARCHITECTURE'>('SHADOW');

  const kpi = computeDashboardKpiMetrics({
    alerts,
    transactions,
    clawbackReceipts,
    reportsByAlertId,
    selfRescuedAmountVnd,
  });
  const benignCount = Math.max(0, falsePositivesSaved);
  const openCount = kpi.openAlertsCount;
  const activeShieldCount = activeShieldRules.filter((r) => r.active).length;
  const firstCaseId = alerts[0]?.id ?? 'ALT-APP-003';

  const triggerDownload = (content: string, fileName: string, mime: string) => {
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = fileName;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-4">
      {/* 1. Focused 3-Second Onboarding Banner (What it does + How to use it) */}
      <section className="bg-gradient-to-br from-slate-900 via-slate-900 to-slate-950 border border-slate-800 rounded-2xl p-4 sm:p-5 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div className="space-y-2 max-w-2xl">
          <h2 className="text-base sm:text-lg font-bold text-white leading-snug">
            Điều tra giao dịch nghi lừa đảo &amp; bật Lá chắn Ví trong &lt;10 giây
          </h2>
          <p className="text-xs text-slate-300 leading-relaxed">
            AegisOps phân tích dòng tiền bằng <strong className="text-white">5 công cụ định lượng + Gemini AI</strong> để phát hiện tài khoản rác và ngăn chuyển tiền nhầm ngay trên Ví MoMo mô phỏng.
          </p>
          {/* Ultra-clear 3-Step Usage Guide */}
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1 pt-0.5 text-[11px] text-slate-400">
            <span className="inline-flex items-center gap-1.5">
              <span className="w-4 h-4 rounded-full bg-slate-800 text-amber-300 font-bold text-[10px] inline-flex items-center justify-center">
                1
              </span>
              Chọn 1 vụ việc bên dưới
            </span>
            <span className="text-slate-600">→</span>
            <span className="inline-flex items-center gap-1.5">
              <span className="w-4 h-4 rounded-full bg-slate-800 text-cyan-300 font-bold text-[10px] inline-flex items-center justify-center">
                2
              </span>
              Bấm <strong className="text-slate-200">AI Điều tra</strong> &amp; duyệt Playbook
            </span>
            <span className="text-slate-600">→</span>
            <span className="inline-flex items-center gap-1.5">
              <span className="w-4 h-4 rounded-full bg-slate-800 text-emerald-300 font-bold text-[10px] inline-flex items-center justify-center">
                3
              </span>
              Thử chuyển tiền trên <strong className="text-slate-200">Ví MoMo</strong> để xem chặn thật
            </span>
          </div>
        </div>

        {/* Only 2 Clear CTAs (Zero Competition) */}
        <div className="flex flex-wrap sm:flex-nowrap items-center gap-2.5 shrink-0">
          <button
            type="button"
            onClick={onRunAutoDemo}
            className="cursor-pointer inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl bg-amber-500 hover:bg-amber-400 text-slate-950 text-xs font-bold shadow-sm transition-colors whitespace-nowrap"
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            <span>Xem Demo Tự động 15s</span>
          </button>
          <button
            type="button"
            onClick={() => onOpenAlertInvestigation(firstCaseId)}
            className="cursor-pointer inline-flex items-center justify-center gap-1.5 px-4 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-white border border-slate-700 text-xs font-semibold transition-colors whitespace-nowrap"
          >
            <span>Mở vụ {firstCaseId}</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </section>

      {/* 2. Slim 4-Metric Strip (Compact, Honest Measured Provenance, Preserves E2E data-testids) */}
      <section className="grid grid-cols-2 xl:grid-cols-4 gap-3">
        <div className="bg-slate-900/75 border border-slate-800/90 rounded-xl px-3.5 py-2.5">
          <div className="flex items-center justify-between text-[11px] text-slate-400">
            <span>Đã chặn &amp; thu hồi</span>
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
          </div>
          <div
            className="text-sm sm:text-base font-bold text-amber-300 mt-1 truncate"
            data-testid="kpi-blocked-recovered-vnd"
          >
            {kpi.totalConfirmedBlockedAndRecoveredVnd > 0
              ? `${kpi.totalConfirmedBlockedAndRecoveredVnd.toLocaleString('vi-VN')} ₫`
              : '0 ₫'}
          </div>
          <div className="text-[11px] text-slate-400 truncate mt-0.5">
            {kpi.transactionsHeldForReviewVnd > 0
              ? `Đang tạm giữ: ${kpi.transactionsHeldForReviewVnd.toLocaleString('vi-VN')} ₫`
              : 'Chưa có GD bị chặn'}
          </div>
        </div>

        <div className="bg-slate-900/75 border border-slate-800/90 rounded-xl px-3.5 py-2.5">
          <div className="flex items-center justify-between text-[11px] text-slate-400">
            <span>Độ trễ AI trung bình</span>
            <Clock className="w-3.5 h-3.5 text-cyan-400" />
          </div>
          <div
            className="text-sm sm:text-base font-bold text-white mt-1 truncate"
            data-testid="kpi-avg-latency"
          >
            {kpi.averageInvestigationLatencyMs !== null
              ? `${(kpi.averageInvestigationLatencyMs / 1000).toFixed(2)}s`
              : 'Chưa có dữ liệu'}
          </div>
          <div className="text-[11px] text-slate-400 truncate mt-0.5">
            {kpi.measuredReportCount > 0
              ? `Đo từ ${kpi.measuredReportCount} lượt điều tra`
              : 'Chạy AI để đo thực tế'}
          </div>
        </div>

        <div className="bg-slate-900/75 border border-slate-800/90 rounded-xl px-3.5 py-2.5">
          <div className="flex items-center justify-between text-[11px] text-slate-400">
            <span>Lá chắn Ví &amp; Chờ duyệt</span>
            <Smartphone className="w-3.5 h-3.5 text-violet-400" />
          </div>
          <div className="text-sm sm:text-base font-bold text-white mt-1 truncate">
            {activeShieldCount} lá chắn{' '}
            <span className="text-xs font-semibold text-amber-300">• {openCount} chờ xử lý</span>
          </div>
          <div className="text-[11px] text-slate-400 truncate mt-0.5">
            Tổng {allAlertsCount} hồ sơ mô phỏng
          </div>
        </div>

        <div className="bg-slate-900/75 border border-slate-800/90 rounded-xl px-3.5 py-2.5">
          <div className="flex items-center justify-between text-[11px] text-slate-400">
            <span>Tránh khóa oan (An toàn)</span>
            <UserCheck className="w-3.5 h-3.5 text-emerald-400" />
          </div>
          <div
            className="text-sm sm:text-base font-bold text-emerald-300 mt-1 truncate"
            data-testid="kpi-benign-alerts"
          >
            {benignCount > 0 ? `${benignCount} cảnh báo` : '0 cảnh báo'}
          </div>
          <div className="text-[11px] text-slate-400 truncate mt-0.5">
            Đóng trạng thái an toàn
          </div>
        </div>
      </section>

      {/* 3. PRIMARY FOCUS ABOVE THE FOLD: Unified Case Queue Table with Inline Risk Bar & Clean Filter Tabs */}
      <section className="bg-slate-900/85 border border-slate-800 rounded-2xl p-4 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2.5">
          <div>
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-amber-400" />
              <span>Danh sách Vụ việc Cần Xử lý ({alerts.length}/{allAlertsCount})</span>
            </h3>
            <p className="text-[11px] text-slate-400 mt-0.5">
              Bấm <strong className="text-amber-300">Điều tra →</strong> ở bất kỳ dòng nào để xem sơ đồ dòng tiền và chạy trợ lý AI.
            </p>
          </div>

          {/* Compact Secondary Actions (New Case + CSV Tools) */}
          <div className="flex flex-wrap items-center gap-1.5 text-xs">
            <button
              type="button"
              onClick={() => onNavigateView('CASE_BUILDER')}
              className="cursor-pointer inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg font-semibold bg-slate-800 hover:bg-slate-700 text-violet-200 border border-slate-700 transition-colors"
            >
              <FilePlus2 className="w-3.5 h-3.5 text-violet-400" />
              <span>Tạo ca mới</span>
            </button>

            {onToggleLiveFeed && (
              <button
                type="button"
                onClick={onToggleLiveFeed}
                className={`cursor-pointer inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg font-semibold border transition-colors ${
                  isLiveFeedEnabled
                    ? 'bg-emerald-500/15 text-emerald-200 border-emerald-500/40'
                    : 'bg-slate-950 hover:bg-slate-800 text-slate-300 border-slate-800'
                }`}
              >
                <Radio
                  className={`w-3.5 h-3.5 ${
                    isLiveFeedEnabled ? 'text-emerald-400 animate-pulse' : 'text-slate-400'
                  }`}
                />
                <span className="hidden sm:inline">{isLiveFeedEnabled ? 'Live: Bật' : 'Live Feed'}</span>
              </button>
            )}

            {onImportBatchFile && (
              <>
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".csv,.json,text/csv,application/json"
                  className="hidden"
                  onChange={async (e) => {
                    const file = e.target.files?.[0];
                    if (!file) return;
                    const text = await file.text();
                    await onImportBatchFile(text, file.name);
                    e.target.value = '';
                  }}
                />
                <button
                  type="button"
                  disabled={isImportingBatch}
                  onClick={() => fileInputRef.current?.click()}
                  title="Nhập hàng loạt vụ việc từ file .CSV hoặc .JSON"
                  className="cursor-pointer inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg font-semibold bg-slate-950 hover:bg-slate-800 text-slate-300 border border-slate-800 transition-colors"
                >
                  <Upload className="w-3.5 h-3.5 text-slate-400" />
                  <span className="hidden md:inline">{isImportingBatch ? 'Đang nạp...' : 'Nhập CSV'}</span>
                </button>
              </>
            )}

            <button
              type="button"
              onClick={() =>
                triggerDownload(
                  generateSampleBatchCsv(),
                  'AegisOps_Batch_Template.csv',
                  'text/csv;charset=utf-8;'
                )
              }
              title="Tải file CSV mẫu"
              className="cursor-pointer inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg font-semibold bg-slate-950 hover:bg-slate-800 text-slate-300 border border-slate-800 transition-colors"
            >
              <FileSpreadsheet className="w-3.5 h-3.5 text-slate-400" />
              <span className="hidden lg:inline">File mẫu</span>
            </button>

            <button
              type="button"
              onClick={() =>
                triggerDownload(
                  exportCasesToCsv(alerts, accounts, forensicsMap),
                  'AegisOps_Report_Export.csv',
                  'text/csv;charset=utf-8;'
                )
              }
              title="Xuất báo cáo ra CSV"
              className="cursor-pointer inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg font-semibold bg-slate-950 hover:bg-slate-800 text-slate-300 border border-slate-800 transition-colors"
            >
              <Download className="w-3.5 h-3.5 text-slate-400" />
              <span className="hidden lg:inline">Xuất CSV</span>
            </button>
          </div>
        </div>

        {/* Clean Monochrome Inline Filter Pills (Replaces the Global Rainbow Tag Box) */}
        {tagOptions.length > 0 && onSelectTagFilter && (
          <div className="flex items-center gap-1.5 overflow-x-auto pb-1">
            {tagOptions
              .filter((t) => t.id === 'ALL' || t.count > 0 || selectedTagFilter === t.id)
              .map((tag) => {
                const active = selectedTagFilter === tag.id;
                return (
                  <button
                    key={tag.id}
                    type="button"
                    onClick={() => onSelectTagFilter(tag.id)}
                    className={`cursor-pointer shrink-0 inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[11px] font-semibold border transition-colors ${
                      active
                        ? 'bg-amber-500 text-slate-950 border-amber-400 font-bold'
                        : 'bg-slate-950/80 text-slate-300 border-slate-800 hover:border-slate-700 hover:text-white'
                    }`}
                  >
                    <span>{tag.labelVi}</span>
                    <span
                      className={`text-[10px] px-1 rounded ${
                        active ? 'bg-slate-950/20 text-slate-950' : 'text-slate-400'
                      }`}
                    >
                      {tag.count}
                    </span>
                  </button>
                );
              })}
          </div>
        )}

        {/* Unified Case Table with Inline Risk Bar */}
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 text-[11px]">
                <th className="py-2 px-3 font-semibold">Vụ việc &amp; Kịch bản</th>
                <th className="py-2 px-3 font-semibold hidden md:table-cell">Tài khoản nhận</th>
                <th className="py-2 px-3 font-semibold w-36">Mức rủi ro</th>
                <th className="py-2 px-3 font-semibold">Trạng thái</th>
                <th className="py-2 px-3 font-semibold text-right">Thao tác</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {alerts.map((alert) => {
                const tagMeta = SCENARIO_TAG_META[alert.scenarioCode];
                const score =
                  forensicsMap[alert.id]?.deterministicRiskScore ?? alert.deterministicRiskScore;
                const targetAcc = accounts.find((a) => a.id === alert.targetRecipientAccountId);
                const isMitigated = alert.status === 'MITIGATED';
                const isSafe = alert.status === 'DISMISSED_SAFE';
                const isLowRisk = score < 30;

                return (
                  <tr key={alert.id} className="hover:bg-slate-800/35 transition-colors">
                    <td className="py-3 px-3 max-w-md">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="font-bold text-amber-300 whitespace-nowrap">
                          {alert.id}
                        </span>
                        <span
                          className={`text-[10px] font-semibold px-1.5 py-0.5 rounded border ${tagMeta.pillClass}`}
                        >
                          {tagMeta.labelVi}
                        </span>
                      </div>
                      <div className="font-semibold text-white leading-snug">{alert.title}</div>
                      <div className="text-[11px] text-slate-400 truncate mt-0.5">
                        {alert.subtitle}
                      </div>
                    </td>

                    <td className="py-3 px-3 hidden md:table-cell">
                      <div className="font-semibold text-slate-200 font-mono text-[11px]">
                        {targetAcc?.accountNumber ?? alert.targetRecipientAccountId}
                      </div>
                      <div className="text-[11px] text-slate-400 truncate max-w-[180px]">
                        {targetAcc?.ownerName ?? alert.targetRecipientAccountId}
                      </div>
                    </td>

                    <td className="py-3 px-3 whitespace-nowrap">
                      <div className="flex items-center justify-between text-[11px] font-bold mb-1">
                        <span
                          className={
                            isLowRisk
                              ? 'text-emerald-400'
                              : score >= 80
                                ? 'text-red-400'
                                : 'text-amber-400'
                          }
                        >
                          {score}/100
                        </span>
                        <span className="text-[10px] font-normal text-slate-500">
                          {isLowRisk ? 'An toàn' : score >= 80 ? 'Rất cao' : 'Cảnh báo'}
                        </span>
                      </div>
                      <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full ${
                            isLowRisk
                              ? 'bg-emerald-500'
                              : score >= 80
                                ? 'bg-gradient-to-r from-amber-500 to-red-500'
                                : 'bg-amber-400'
                          }`}
                          style={{ width: `${Math.max(8, score)}%` }}
                        />
                      </div>
                    </td>

                    <td className="py-3 px-3 whitespace-nowrap">
                      {isMitigated ? (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-emerald-500/15 text-emerald-300 border border-emerald-500/25 text-[11px] font-semibold">
                          <Lock className="w-3 h-3" /> Đã bật Lá chắn
                        </span>
                      ) : isSafe ? (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-cyan-500/15 text-cyan-300 border border-cyan-500/25 text-[11px] font-semibold">
                          <CheckCircle2 className="w-3 h-3" /> Hợp lệ
                        </span>
                      ) : pendingL2ApprovalAlertIds.includes(alert.id) ? (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-violet-500/15 text-violet-200 border border-violet-500/30 text-[11px] font-semibold">
                          Chờ L2 duyệt
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-amber-500/10 text-amber-300 border border-amber-500/25 text-[11px] font-semibold">
                          Chờ xử lý
                        </span>
                      )}
                    </td>

                    <td className="py-3 px-3 text-right whitespace-nowrap">
                      <div className="inline-flex items-center gap-1.5">
                        <button
                          type="button"
                          onClick={() => onEditAlertSpec(alert.id)}
                          title="Chỉnh sửa thông số kịch bản"
                          className="cursor-pointer p-1.5 rounded-lg bg-slate-950 hover:bg-slate-800 text-slate-400 hover:text-white border border-slate-800 transition-colors"
                        >
                          <SlidersHorizontal className="w-3.5 h-3.5" />
                        </button>
                        <button
                          type="button"
                          onClick={() => onOpenAlertInvestigation(alert.id)}
                          className="cursor-pointer inline-flex items-center gap-1 px-3 py-1.5 rounded-lg bg-amber-500 hover:bg-amber-400 text-slate-950 font-bold transition-colors"
                        >
                          <span>Điều tra</span>
                          <ArrowRight className="w-3 h-3" />
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
              {alerts.length === 0 && (
                <tr>
                  <td colSpan={5} className="py-8 text-center text-slate-400">
                    Không có vụ việc nào khớp bộ lọc hiện tại. Hãy chọn &ldquo;Tất cả&rdquo; hoặc xóa từ khóa tìm kiếm.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      {/* 4. Optional Collapsible Technical Reference (Shadow Mode Benchmark + 4-Layer Architecture) */}
      <section className="bg-slate-900/60 border border-slate-800/80 rounded-2xl overflow-hidden">
        <button
          type="button"
          onClick={() => setShowDetailsPanel((v) => !v)}
          className="cursor-pointer w-full px-4 py-3 flex items-center justify-between text-left hover:bg-slate-800/30 transition-colors"
        >
          <div className="flex items-center gap-2 text-xs font-semibold text-slate-300">
            <Layers className="w-4 h-4 text-cyan-400" />
            <span>
              Xem thêm cho Giám khảo: Đối chứng Rule Cũ vs AegisOps AI &amp; Kiến trúc Bảo vệ 4 Tầng
            </span>
          </div>
          <span className="inline-flex items-center gap-1 text-[11px] text-slate-400 shrink-0">
            <span>{showDetailsPanel ? 'Thu gọn' : 'Mở rộng'}</span>
            {showDetailsPanel ? (
              <ChevronUp className="w-4 h-4" />
            ) : (
              <ChevronDown className="w-4 h-4" />
            )}
          </span>
        </button>

        {showDetailsPanel && (
          <div className="px-4 pb-4 pt-1 border-t border-slate-800/80 space-y-3">
            <div className="flex items-center justify-between flex-wrap gap-2">
              <div className="inline-flex p-1 rounded-xl bg-slate-950 border border-slate-800 text-xs">
                <button
                  type="button"
                  onClick={() => setDetailsTab('SHADOW')}
                  className={`cursor-pointer px-3 py-1 rounded-lg font-semibold transition-colors ${
                    detailsTab === 'SHADOW'
                      ? 'bg-slate-800 text-white'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  Đối chứng Shadow Mode
                </button>
                <button
                  type="button"
                  onClick={() => setDetailsTab('ARCHITECTURE')}
                  className={`cursor-pointer px-3 py-1 rounded-lg font-semibold transition-colors ${
                    detailsTab === 'ARCHITECTURE'
                      ? 'bg-slate-800 text-white'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  Kiến trúc 4 Tầng
                </button>
              </div>

              <button
                type="button"
                onClick={() => onNavigateView('COMPLIANCE_AUDIT')}
                className="cursor-pointer text-xs font-semibold text-cyan-300 hover:text-cyan-200"
              >
                Xem Nhật ký &amp; Pháp lý ({auditLogs.length}) →
              </button>
            </div>

            {detailsTab === 'SHADOW' ? (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                {alerts.slice(0, 4).map((alert) => {
                  const suite = forensicsMap[alert.id];
                  const score = suite?.deterministicRiskScore ?? alert.deterministicRiskScore;
                  const isSafe = score < 30;
                  return (
                    <div
                      key={`shadow-${alert.id}`}
                      className="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-2"
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-bold text-amber-300">{alert.id}</span>
                        <span
                          className={`px-2 py-0.5 rounded-md font-bold text-[11px] ${
                            isSafe
                              ? 'bg-emerald-500/15 text-emerald-300'
                              : 'bg-red-500/15 text-red-300'
                          }`}
                        >
                          AegisOps: {score}/100
                        </span>
                      </div>
                      <div className="text-slate-200 font-semibold">{alert.title}</div>
                      <div className="p-2 rounded-lg bg-slate-900 text-slate-400">
                        <strong className="text-rose-300">Rule cũ:</strong>{' '}
                        {alert.traditionalRuleReason}
                      </div>
                      <div className="p-2 rounded-lg bg-emerald-950/30 border border-emerald-500/20 text-emerald-200">
                        <strong>AegisOps:</strong>{' '}
                        {suite?.fallbackReport.recommendedActions[0]?.labelVi ?? 'Xử lý chính xác'}
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-2.5 text-xs">
                {[
                  {
                    step: 'Tầng 1 • Input & Telemetry',
                    desc: 'Giao dịch, ảnh chat OCR, VietQR EMVCo & tín hiệu QĐ 2345.',
                    accent: 'border-violet-500/30 text-violet-200',
                  },
                  {
                    step: 'Tầng 2 • 5 Công cụ Định lượng',
                    desc: 'Z-Score, BFS Mule Ring, Smurfing Entropy & kiểm tra ATO/HMAC.',
                    accent: 'border-cyan-500/30 text-cyan-200',
                  },
                  {
                    step: 'Tầng 3 • Gemini AI + Citation Gate',
                    desc: 'Suy luận giải thích bằng tiếng Việt, kiểm định mã bằng chứng tồn tại.',
                    accent: 'border-amber-500/30 text-amber-200',
                  },
                  {
                    step: 'Tầng 4 • Lá chắn Ví Mô phỏng',
                    desc: 'Đèn 3 màu, chặn STK lừa đảo & hoàn tiền Clawback sổ cái kép.',
                    accent: 'border-emerald-500/30 text-emerald-200',
                  },
                ].map((layer) => (
                  <div
                    key={layer.step}
                    className={`p-3 rounded-xl bg-slate-950 border ${layer.accent}`}
                  >
                    <div className="font-bold">{layer.step}</div>
                    <div className="text-[11px] text-slate-400 mt-1 leading-relaxed">
                      {layer.desc}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </section>
    </div>
  );
};
