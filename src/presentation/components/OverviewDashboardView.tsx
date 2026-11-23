'use client';

import { useRef } from 'react';
import {
  Activity,
  ArrowRight,
  BarChart3,
  CheckCircle2,
  Clock,
  Download,
  FilePlus2,
  FileSpreadsheet,
  Lock,
  Play,
  Radio,
  SearchCode,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  Smartphone,
  Sparkles,
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
    labelVi: 'Chống lừa đảo • APP Fraud',
    pillClass: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
  },
  CYBER_ATO_MULE: {
    labelVi: 'An ninh mạng • Chiếm đoạt ATO',
    pillClass: 'bg-red-500/15 text-red-300 border-red-500/30',
  },
  BUSINESS_LOGIC_RACE: {
    labelVi: 'An ninh API • Race Condition',
    pillClass: 'bg-violet-500/15 text-violet-300 border-violet-500/30',
  },
  SMART_FALSE_POSITIVE: {
    labelVi: 'Nhân văn • Tránh khóa oan',
    pillClass: 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30',
  },
  CUSTOM_SANDBOX: {
    labelVi: 'Hồ sơ Tự nhập • Sandbox',
    pillClass: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
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
  onOpenAlertInvestigation,
  onEditAlertSpec,
  onNavigateView,
  onRunAutoDemo,
  onImportBatchFile,
  onToggleLiveFeed,
}: OverviewDashboardViewProps) => {
  void _mitigatedCount;
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const kpi = computeDashboardKpiMetrics({
    alerts,
    transactions,
    clawbackReceipts,
    reportsByAlertId,
    selfRescuedAmountVnd,
  });
  const benignCount = Math.max(0, falsePositivesSaved);
  const openCount = kpi.openAlertsCount;

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
      {/* 1. Commercial Onboarding Hero / Quick Launcher Banner */}
      <section className="bg-gradient-to-r from-slate-900 via-slate-900 to-slate-950 border border-slate-800 rounded-2xl p-4 sm:p-5 flex flex-col xl:flex-row xl:items-center justify-between gap-4 shadow-lg">
        <div className="space-y-1.5 max-w-2xl">
          <div className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-lg bg-amber-500/15 border border-amber-500/30 text-amber-300 text-xs font-bold">
            <Sparkles className="w-3.5 h-3.5" />
            <span>AegisOps Enterprise Risk &amp; Anti-Scam Portal</span>
          </div>
          <h2 className="text-base sm:text-lg font-bold text-white">
            Chào mừng đến Trung tâm Vận hành Điều tra &amp; Bảo vệ Ví Thời gian thực
          </h2>
          <p className="text-xs text-slate-300 leading-relaxed">
            Chọn một hồ sơ giao dịch bên dưới để điều tra đa nguồn trong <strong className="text-emerald-400">&lt;10 giây</strong>, tự nhập dữ liệu giao dịch thật của bạn qua <strong className="text-violet-300">Biểu mẫu 4 Phần</strong>, hoặc kiểm chứng trực tiếp cơ chế chặn giao dịch trên <strong className="text-cyan-300">Ví MoMo</strong>.
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5 shrink-0">
          <button
            type="button"
            onClick={() => onNavigateView('CASE_BUILDER')}
            className="cursor-pointer p-3 rounded-xl bg-violet-600/20 hover:bg-violet-600/30 border border-violet-500/40 text-left transition-all"
          >
            <FilePlus2 className="w-4 h-4 text-violet-300 mb-1.5" />
            <div className="text-xs font-bold text-white">1. Nhập Hồ sơ Thực tế</div>
            <div className="text-[11px] text-slate-300 mt-0.5">Form 4 Phần &amp; Quét ảnh OCR</div>
          </button>

          <button
            type="button"
            onClick={() => onNavigateView('INVESTIGATION')}
            className="cursor-pointer p-3 rounded-xl bg-cyan-500/15 hover:bg-cyan-500/25 border border-cyan-500/40 text-left transition-all"
          >
            <SearchCode className="w-4 h-4 text-cyan-300 mb-1.5" />
            <div className="text-xs font-bold text-white">2. Vào Bàn Điều tra</div>
            <div className="text-[11px] text-slate-300 mt-0.5">Đồ thị BFS &amp; Trợ lý Gemini</div>
          </button>

          <button
            type="button"
            onClick={onRunAutoDemo}
            className="cursor-pointer p-3 rounded-xl bg-amber-500 hover:bg-amber-400 text-slate-950 text-left transition-all shadow-sm"
          >
            <Play className="w-4 h-4 fill-current mb-1.5" />
            <div className="text-xs font-bold">3. Chạy Demo Khép kín</div>
            <div className="text-[11px] font-semibold opacity-85 mt-0.5">Tự động 15 giây A→Z</div>
          </button>
        </div>
      </section>

      {/* 2. Top 4 Executive KPI Cards (100% Measured Data Provenance — Zero Fabricated Offsets) */}
      <section className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-3.5">
        <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-4 space-y-2 shadow">
          <div className="flex items-center justify-between text-xs text-slate-400 font-semibold">
            <span>Giá trị Giao dịch Chặn &amp; Thu hồi</span>
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-xl font-bold text-amber-300" data-testid="kpi-blocked-recovered-vnd">
            {kpi.totalConfirmedBlockedAndRecoveredVnd > 0
              ? `${kpi.totalConfirmedBlockedAndRecoveredVnd.toLocaleString('vi-VN')} ₫`
              : 'Chưa có dữ liệu (0 ₫)'}
          </div>
          <div className="text-[11px] text-emerald-400 font-semibold">
            {kpi.transactionsHeldForReviewVnd > 0
              ? `Đang tạm giữ chờ rà soát (HELD): ${kpi.transactionsHeldForReviewVnd.toLocaleString('vi-VN')} ₫${kpi.recoveredClawbackVnd > 0 ? ` • Đã hoàn: ${kpi.recoveredClawbackVnd.toLocaleString('vi-VN')} ₫` : ''}`
              : kpi.recoveredClawbackVnd > 0
                ? `Đã thu hồi Clawback: ${kpi.recoveredClawbackVnd.toLocaleString('vi-VN')} ₫`
                : 'Nguồn: Giao dịch BLOCKED + Clawback + Tự hủy'}
          </div>
        </div>

        <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-4 space-y-2 shadow">
          <div className="flex items-center justify-between text-xs text-slate-400 font-semibold">
            <span>Độ trễ Điều tra Đo lường Trung bình</span>
            <Clock className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-xl font-bold text-white" data-testid="kpi-avg-latency">
            {kpi.averageInvestigationLatencyMs !== null ? (
              <>
                {kpi.averageInvestigationLatencyMs.toLocaleString('vi-VN')} ms{' '}
                <span className="text-xs font-semibold text-slate-400">
                  ({(kpi.averageInvestigationLatencyMs / 1000).toFixed(2)} giây)
                </span>
              </>
            ) : (
              <span className="text-slate-300">Chưa có dữ liệu</span>
            )}
          </div>
          <div className="text-[11px] text-cyan-300 font-semibold">
            {kpi.measuredReportCount > 0
              ? `Đo trung bình từ ${kpi.measuredReportCount} phiên điều tra thực tế`
              : 'Chạy AI Điều tra để ghi nhận độ trễ thực đo'}
          </div>
        </div>

        <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-4 space-y-2 shadow">
          <div className="flex items-center justify-between text-xs text-slate-400 font-semibold">
            <span>Lá chắn Cộng đồng đang bật</span>
            <Smartphone className="w-4 h-4 text-violet-400" />
          </div>
          <div className="text-xl font-bold text-white">
            {activeShieldRules.filter((r) => r.active).length} quy tắc{' '}
            <span className="text-xs font-semibold text-amber-300">
              • {openCount} vụ chờ duyệt
            </span>
          </div>
          <div className="text-[11px] text-slate-300">
            Nguồn: Quy tắc đang hoạt động trên phiên làm việc
          </div>
        </div>

        <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-4 space-y-2 shadow">
          <div className="flex items-center justify-between text-xs text-slate-400 font-semibold">
            <span>Cảnh báo Đánh dấu Hợp lệ (Benign)</span>
            <UserCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-xl font-bold text-emerald-300" data-testid="kpi-benign-alerts">
            {benignCount > 0 ? `${benignCount} cảnh báo hợp lệ` : '0 cảnh báo (Chưa có dữ liệu)'}
          </div>
          <div className="text-[11px] text-slate-300">
            Nguồn: Cảnh báo đóng trạng thái DISMISSED_SAFE (Mô phỏng)
          </div>
        </div>
      </section>

      {/* 3. Visual Analytics Row (2 Side-by-Side Charts) */}
      <section className="grid grid-cols-1 xl:grid-cols-12 gap-3.5">
        {/* Chart 1: Interactive Risk Distribution Bar Chart */}
        <div className="xl:col-span-7 bg-slate-900/90 border border-slate-800 rounded-2xl p-4 space-y-3 shadow">
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <BarChart3 className="w-4 h-4 text-amber-400" />
              <h3 className="text-sm font-bold text-white">
                Biểu đồ Phân bổ Điểm Rủi ro theo Vụ việc (Bấm để mở Điều tra)
              </h3>
            </div>
            <span className="text-xs text-slate-400">Hiển thị {alerts.length}/{allAlertsCount} vụ</span>
          </div>

          <div className="space-y-2.5">
            {alerts.map((alert) => {
              const score = forensicsMap[alert.id]?.deterministicRiskScore ?? alert.deterministicRiskScore;
              const isSafe = score < 30;
              return (
                <button
                  key={alert.id}
                  type="button"
                  onClick={() => onOpenAlertInvestigation(alert.id)}
                  className="cursor-pointer w-full text-left p-2.5 rounded-xl bg-slate-950 hover:bg-slate-800/70 border border-slate-800 transition-colors space-y-1.5"
                >
                  <div className="flex items-center justify-between gap-2 text-xs">
                    <span className="font-bold text-white truncate">
                      {alert.id} — {alert.title}
                    </span>
                    <span
                      className={`font-bold shrink-0 ${isSafe ? 'text-emerald-400' : score >= 80 ? 'text-red-400' : 'text-amber-400'
                        }`}
                    >
                      {score}/100
                    </span>
                  </div>
                  <div className="w-full h-2 bg-slate-900 rounded-full overflow-hidden">
                    <div
                      className={`h-full rounded-full transition-all duration-500 ${isSafe
                        ? 'bg-emerald-500'
                        : score >= 80
                          ? 'bg-gradient-to-r from-amber-500 to-red-500'
                          : 'bg-amber-400'
                        }`}
                      style={{ width: `${Math.max(8, score)}%` }}
                    />
                  </div>
                </button>
              );
            })}
          </div>
        </div>

        {/* Chart 2: Closed-Loop Architecture & Real-Time Activity Summary */}
        <div className="xl:col-span-5 bg-slate-900/90 border border-slate-800 rounded-2xl p-4 flex flex-col justify-between gap-3 shadow">
          <div className="space-y-3">
            <div className="flex items-center gap-2">
              <Activity className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-bold text-white">
                Kiến trúc Bảo vệ Vòng khép kín 4 Tầng
              </h3>
            </div>

            <div className="space-y-2 text-xs">
              {[
                {
                  step: 'Tầng 1 • Input & Telemetry',
                  desc: 'Thu thập Giao dịch, Ảnh Chat, VietQR EMVCo & Hành vi Cuộc gọi QĐ 2345',
                  color: 'border-violet-500/40 bg-violet-500/10 text-violet-200',
                },
                {
                  step: 'Tầng 2 • 5 Công cụ Định lượng (Quyết định gốc)',
                  desc: 'Tính Z-Score, BFS Mule Ring, Smurfing Entropy & Kiểm tra ATO/HMAC',
                  color: 'border-cyan-500/40 bg-cyan-500/10 text-cyan-200',
                },
                {
                  step: 'Tầng 3 • Trợ lý Gemini + Kiểm định Tham chiếu Trích dẫn',
                  desc: 'Suy luận liên miền hỗ trợ điều tra, kiểm định mã bằng chứng tồn tại & giữ nguyên quyền quyết định định lượng',
                  color: 'border-amber-500/40 bg-amber-500/10 text-amber-200',
                },
                {
                  step: 'Tầng 4 • Lá chắn Ví Mô phỏng (Đánh giá cục bộ)',
                  desc: 'Đèn 3 màu, chặn STK lừa đảo & Thẻ giải nhiệt tâm lý nạn nhân (môi trường demo mô phỏng)',
                  color: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-200',
                },
              ].map((layer) => (
                <div key={layer.step} className={`p-2.5 rounded-xl border ${layer.color}`}>
                  <div className="font-bold">{layer.step}</div>
                  <div className="text-[11px] opacity-90 mt-0.5">{layer.desc}</div>
                </div>
              ))}
            </div>
          </div>

          <div className="pt-2 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400">
            <span>Nhật ký hệ thống gần nhất: {auditLogs.length} bản ghi</span>
            <button
              type="button"
              onClick={() => onNavigateView('COMPLIANCE_AUDIT')}
              className="cursor-pointer font-bold text-cyan-300 hover:text-cyan-200"
            >
              Xem Nhật ký &amp; Pháp lý →
            </button>
          </div>
        </div>
      </section>

      {/* 4. Commercial Interactive Case Table + Batch CSV/JSON I/O Bar */}
      <section className="bg-slate-900/90 border border-slate-800 rounded-2xl p-4 space-y-3 shadow">
        <div className="flex flex-wrap items-center justify-between gap-2.5">
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-amber-400" />
            <h3 className="text-sm font-bold text-white">
              Bảng Danh sách Vụ việc &amp; Nhập/Xuất Dữ liệu Thực tế ({alerts.length})
            </h3>
          </div>

          <div className="flex flex-wrap items-center gap-2 text-xs">
            {onToggleLiveFeed && (
              <button
                type="button"
                onClick={onToggleLiveFeed}
                className={`cursor-pointer inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-xl font-bold border transition-colors ${isLiveFeedEnabled
                  ? 'bg-emerald-500/20 text-emerald-200 border-emerald-400'
                  : 'bg-slate-950 hover:bg-slate-800 text-slate-300 border-slate-700'
                  }`}
              >
                <Radio className={`w-3.5 h-3.5 ${isLiveFeedEnabled ? 'text-emerald-400 animate-pulse' : 'text-slate-400'}`} />
                <span>{isLiveFeedEnabled ? 'Đang bật Live Feed' : 'Bật Cảnh báo Live'}</span>
              </button>
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
              className="cursor-pointer inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-xl font-bold bg-slate-950 hover:bg-slate-800 text-cyan-300 border border-slate-700 transition-colors"
            >
              <FileSpreadsheet className="w-3.5 h-3.5" />
              <span>Tải File Mẫu (.CSV)</span>
            </button>

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
                  className="cursor-pointer inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-xl font-bold bg-violet-600/25 hover:bg-violet-600/40 text-violet-200 border border-violet-500/40 transition-colors"
                >
                  <Upload className="w-3.5 h-3.5" />
                  <span>{isImportingBatch ? 'Đang nạp...' : 'Nhập Hàng loạt (.CSV/.JSON)'}</span>
                </button>
              </>
            )}

            <button
              type="button"
              onClick={() =>
                triggerDownload(
                  exportCasesToCsv(alerts, accounts, forensicsMap),
                  'AegisOps_Report_Export.csv',
                  'text/csv;charset=utf-8;'
                )
              }
              className="cursor-pointer inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-xl font-bold bg-slate-950 hover:bg-slate-800 text-emerald-300 border border-slate-700 transition-colors"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Xuất Báo cáo (.CSV)</span>
            </button>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400">
                <th className="py-2.5 px-3 font-bold">Mã Vụ việc</th>
                <th className="py-2.5 px-3 font-bold">Phân loại &amp; Kịch bản</th>
                <th className="py-2.5 px-3 font-bold">Tài khoản Nhận Đích</th>
                <th className="py-2.5 px-3 font-bold">Điểm Rủi ro</th>
                <th className="py-2.5 px-3 font-bold">Trạng thái</th>
                <th className="py-2.5 px-3 font-bold text-right">Thao tác</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80">
              {alerts.map((alert) => {
                const tagMeta = SCENARIO_TAG_META[alert.scenarioCode];
                const score =
                  forensicsMap[alert.id]?.deterministicRiskScore ?? alert.deterministicRiskScore;
                const targetAcc = accounts.find((a) => a.id === alert.targetRecipientAccountId);
                const isMitigated = alert.status === 'MITIGATED';
                const isSafe = alert.status === 'DISMISSED_SAFE';

                return (
                  <tr
                    key={alert.id}
                    className="hover:bg-slate-800/40 transition-colors"
                  >
                    <td className="py-3 px-3 font-bold text-amber-300 whitespace-nowrap">
                      {alert.id}
                    </td>
                    <td className="py-3 px-3 max-w-md">
                      <span
                        className={`inline-block text-[11px] font-bold px-2 py-0.5 rounded-md border mb-1 ${tagMeta.pillClass}`}
                      >
                        {tagMeta.labelVi}
                      </span>
                      <div className="font-bold text-white leading-snug">{alert.title}</div>
                      <div className="text-[11px] text-slate-400 truncate">{alert.subtitle}</div>
                    </td>
                    <td className="py-3 px-3">
                      <div className="font-bold text-slate-100">
                        {targetAcc?.accountNumber ?? alert.targetRecipientAccountId}
                      </div>
                      <div className="text-[11px] text-slate-400">
                        {targetAcc?.ownerName ?? alert.targetRecipientAccountId}
                      </div>
                    </td>
                    <td className="py-3 px-3 whitespace-nowrap">
                      <span
                        className={`font-bold px-2.5 py-1 rounded-lg border ${score >= 80
                          ? 'bg-red-500/20 text-red-300 border-red-500/30'
                          : score < 30
                            ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30'
                            : 'bg-amber-500/20 text-amber-300 border-amber-500/30'
                          }`}
                      >
                        {score}/100
                      </span>
                    </td>
                    <td className="py-3 px-3 whitespace-nowrap">
                      {isMitigated ? (
                        <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 font-bold">
                          <Lock className="w-3 h-3" /> Đã bật Lá chắn
                        </span>
                      ) : isSafe ? (
                        <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 font-bold">
                          <CheckCircle2 className="w-3 h-3" /> An toàn (Không khóa oan)
                        </span>
                      ) : pendingL2ApprovalAlertIds.includes(alert.id) ? (
                        <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-violet-500/20 text-violet-200 border border-violet-500/40 font-bold">
                          L1 Đã trình — Chờ L2
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-amber-500/15 text-amber-300 border border-amber-500/30 font-bold">
                          Chờ xử lý
                        </span>
                      )}
                    </td>
                    <td className="py-3 px-3 text-right whitespace-nowrap">
                      <div className="inline-flex items-center gap-1.5">
                        <button
                          type="button"
                          onClick={() => onEditAlertSpec(alert.id)}
                          className="cursor-pointer inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-slate-950 hover:bg-slate-800 text-slate-200 border border-slate-700 font-bold"
                        >
                          <SlidersHorizontal className="w-3 h-3 text-violet-400" />
                          <span>Sửa Thông số</span>
                        </button>
                        <button
                          type="button"
                          onClick={() => onOpenAlertInvestigation(alert.id)}
                          className="cursor-pointer inline-flex items-center gap-1 px-3 py-1.5 rounded-lg bg-amber-500 hover:bg-amber-400 text-slate-950 font-bold"
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
                  <td colSpan={6} className="py-8 text-center text-slate-400">
                    Không có vụ việc nào khớp với bộ lọc hiện tại. Hãy chọn Tag &ldquo;Tất cả&rdquo; hoặc xóa từ khóa tìm kiếm.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      {/* 5. Shadow Mode Benchmark Matrix: Legacy Static Rules vs. AegisOps Hybrid AI */}
      <section className="bg-slate-900/90 border border-slate-800 rounded-2xl p-4 space-y-3 shadow">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <BarChart3 className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-bold text-white">
              Bảng Đối chứng Shadow Mode: Hệ thống Rule Cũ Truyền thống vs. AegisOps Hybrid AI
            </h3>
          </div>
          <span className="text-xs font-bold px-2.5 py-0.5 rounded-lg bg-cyan-500/15 text-cyan-300 border border-cyan-500/30">
            Chứng minh Thực nghiệm Độ chính xác
          </span>
        </div>

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
                    className={`px-2 py-0.5 rounded-md font-bold text-[11px] ${isSafe
                      ? 'bg-emerald-500/20 text-emerald-300'
                      : 'bg-red-500/20 text-red-300'
                      }`}
                  >
                    AegisOps: {score}/100
                  </span>
                </div>
                <div className="text-slate-100 font-semibold">{alert.title}</div>
                <div className="p-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-400">
                  <strong className="text-rose-300">Rule Cũ Truyền thống:</strong>{' '}
                  {alert.traditionalRuleReason}
                </div>
                <div className="p-2 rounded-lg bg-emerald-950/35 border border-emerald-500/30 text-emerald-200">
                  <strong>AegisOps AI + Đồ thị:</strong>{' '}
                  {suite?.fallbackReport.recommendedActions[0]?.labelVi ?? 'Xử lý chính xác tức thời'}
                </div>
              </div>
            );
          })}
        </div>
      </section>
    </div>
  );
};
