'use client';

import { useMemo, useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  FlaskConical,
  Link2,
  Lock,
  PlusCircle,
  ShieldAlert,
  UserCheck,
  Zap,
} from 'lucide-react';
import { computeCrossCaseCorrelations } from '@/domain/campaign-correlator';
import type { ForensicSuiteOutput, FraudAlert } from '@/domain/types';

interface AlertTriageQueueProps {
  alerts: FraudAlert[];
  forensicsMap?: Record<string, ForensicSuiteOutput>;
  selectedAlertId: string;
  compactHorizontal?: boolean;
  canExecuteBatchTriage?: boolean;
  onSelectAlert: (alertId: string) => void;
  onOpenSandbox: () => void;
  onExecuteBatchTriage?: () => Promise<boolean>;
}

const SCENARIO_BADGE: Record<FraudAlert['scenarioCode'], { label: string; color: string }> = {
  MULTIMODAL_APP_FRAUD: {
    label: 'Chống lừa đảo • Giả danh Công an',
    color: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
  },
  CYBER_ATO_MULE: {
    label: 'An ninh mạng • Chiếm đoạt TK (ATO)',
    color: 'bg-red-500/15 text-red-300 border-red-500/30',
  },
  BUSINESS_LOGIC_RACE: {
    label: 'An ninh mạng • Lỗi Race Condition',
    color: 'bg-violet-500/15 text-violet-300 border-violet-500/30',
  },
  SMART_FALSE_POSITIVE: {
    label: 'Trợ lý AI • Tránh khóa oan khách',
    color: 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30',
  },
  CUSTOM_SANDBOX: {
    label: 'Kịch bản Tự tạo (Live Sandbox)',
    color: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
  },
};

export const AlertTriageQueue = ({
  alerts,
  forensicsMap = {},
  selectedAlertId,
  compactHorizontal = false,
  canExecuteBatchTriage = true,
  onSelectAlert,
  onOpenSandbox,
  onExecuteBatchTriage,
}: AlertTriageQueueProps) => {
  const [showBatchTriage, setShowBatchTriage] = useState(false);
  const [isExecutingBatch, setIsExecutingBatch] = useState(false);
  const [batchErrorVi, setBatchErrorVi] = useState<string | null>(null);

  const triageSummary = useMemo(
    () => computeCrossCaseCorrelations(alerts, forensicsMap),
    [alerts, forensicsMap]
  );

  const handleRunBatchTriage = async () => {
    if (!onExecuteBatchTriage || isExecutingBatch) return;
    setBatchErrorVi(null);
    setIsExecutingBatch(true);
    try {
      const ok = await onExecuteBatchTriage();
      if (!ok) {
        setBatchErrorVi('Không thể thực thi Gom nhóm AI (Kiểm tra quyền L2 hoặc kết nối API).');
      }
    } catch {
      setBatchErrorVi('Lỗi kết nối khi thực thi Gom nhóm AI.');
    } finally {
      setIsExecutingBatch(false);
    }
  };

  if (compactHorizontal) {
    return (
      <section className="bg-slate-900/90 border border-slate-800 rounded-2xl p-3.5 space-y-2.5 shadow-lg">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2 overflow-x-auto pb-0.5 flex-1">
            <div className="flex items-center gap-2 shrink-0 pr-2">
              <ShieldAlert className="w-4 h-4 text-amber-400" />
              <h2 className="text-sm font-bold text-white">
                Danh sách Vụ việc ({alerts.length}):
              </h2>
            </div>
            {alerts.map((alert, idx) => {
              const active = alert.id === selectedAlertId;
              const liveScore =
                forensicsMap[alert.id]?.deterministicRiskScore ?? alert.deterministicRiskScore;
              return (
                <button
                  key={alert.id}
                  type="button"
                  onClick={() => onSelectAlert(alert.id)}
                  className={`cursor-pointer shrink-0 px-3 py-1.5 rounded-xl border text-xs font-bold flex items-center gap-2 transition-all ${
                    active
                      ? 'bg-slate-800 border-amber-400 text-white ring-1 ring-amber-400/40'
                      : 'bg-slate-950/80 border-slate-800 text-slate-300 hover:text-white'
                  }`}
                >
                  <span className="text-amber-400">Vụ #{idx + 1}</span>
                  <span>({alert.id})</span>
                  <span
                    className={`text-[11px] font-bold px-2 py-0.5 rounded-md ${
                      liveScore >= 80
                        ? 'bg-red-500/20 text-red-300'
                        : 'bg-emerald-500/20 text-emerald-300'
                    }`}
                  >
                    {liveScore}/100
                  </span>
                </button>
              );
            })}
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <button
              type="button"
              onClick={() => setShowBatchTriage((v) => !v)}
              className={`cursor-pointer inline-flex items-center gap-1 px-2.5 py-1.5 rounded-xl text-xs font-bold border transition-colors ${
                showBatchTriage
                  ? 'bg-cyan-500/20 text-cyan-200 border-cyan-400'
                  : 'bg-slate-950 hover:bg-slate-800 text-cyan-300 border-slate-700'
              }`}
            >
              <Zap className="w-3.5 h-3.5" />
              <span>Gom nhóm AI</span>
            </button>
            <button
              type="button"
              onClick={onOpenSandbox}
              className="cursor-pointer shrink-0 inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-slate-950 hover:bg-slate-800 border border-slate-700 text-xs font-bold text-slate-200"
            >
              <PlusCircle className="w-3.5 h-3.5 text-amber-400" />
              <span>+ Tạo Vụ việc Sandbox</span>
            </button>
          </div>
        </div>

        {showBatchTriage && (
          <div className="bg-slate-950 border border-cyan-500/40 rounded-xl p-3 flex flex-wrap items-center justify-between gap-2.5 text-xs">
            <div className="space-y-1 flex-1 min-w-[240px]">
              <div className="font-bold text-cyan-300 flex items-center gap-1.5">
                <Link2 className="w-3.5 h-3.5" />
                <span>
                  Liên kết cụm: {triageSummary.linkedCampaignClusters.length} cụm • Gợi ý đóng an toàn:{' '}
                  {triageSummary.autoClearCandidateIds.join(', ') || '0'}
                </span>
              </div>
              {batchErrorVi && <div className="text-red-300 font-semibold">{batchErrorVi}</div>}
            </div>
            {onExecuteBatchTriage && (
              canExecuteBatchTriage ? (
                <button
                  type="button"
                  disabled={isExecutingBatch}
                  onClick={() => void handleRunBatchTriage()}
                  className="cursor-pointer disabled:opacity-60 px-3.5 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs flex items-center gap-1.5 transition-colors shrink-0"
                >
                  <Zap className="w-3.5 h-3.5" />
                  <span>
                    {isExecutingBatch
                      ? 'Đang khóa cụm & Auto-Clear...'
                      : 'Thực thi Gom nhóm 1-Chạm'}
                  </span>
                </button>
              ) : (
                <span className="text-[11px] text-amber-300 font-semibold">
                  Chỉ Quản lý Rủi ro L2 (Checker) mới được thực thi Gom nhóm 1-Chạm.
                </span>
              )
            )}
          </div>
        )}
      </section>
    );
  }

  return (
    <aside className="bg-slate-900/90 border border-slate-800 rounded-2xl p-4 flex flex-col gap-3 h-full shadow-lg">
      {/* Header matching MoneyFlowGraphCanvas style */}
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-amber-400" />
          <h2 className="text-sm font-bold text-white">
            Danh sách Vụ việc &amp; Phân loại ({alerts.length})
          </h2>
        </div>

        <button
          type="button"
          onClick={() => setShowBatchTriage((v) => !v)}
          className={`cursor-pointer inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-xs font-bold border transition-colors shrink-0 ${
            showBatchTriage
              ? 'bg-cyan-500/20 text-cyan-200 border-cyan-400'
              : 'bg-slate-950 hover:bg-slate-800 text-cyan-300 border-slate-700'
          }`}
        >
          <Zap className="w-3.5 h-3.5" />
          <span>Gom nhóm AI</span>
        </button>
      </div>

      {showBatchTriage && (
        <div className="bg-slate-950 border border-cyan-500/40 rounded-xl p-3 space-y-1.5 text-xs">
          <div className="font-bold text-cyan-300 flex items-center gap-1.5">
            <Link2 className="w-3.5 h-3.5" />
            <span>Phát hiện Liên kết Đa Vụ án:</span>
          </div>
          {triageSummary.linkedCampaignClusters.map((c) => (
            <div key={c.sharedEntityId} className="text-slate-200 bg-slate-900 p-2 rounded-lg border border-slate-800">
              • {c.descriptionVi}
            </div>
          ))}
          {triageSummary.autoClearCandidateIds.length > 0 && (
            <div className="text-emerald-300 bg-emerald-950/40 p-2 rounded-lg border border-emerald-500/30">
              ✓ Gợi ý đóng nhanh (Báo động giả):{' '}
              <strong>{triageSummary.autoClearCandidateIds.join(', ')}</strong>
            </div>
          )}
          {onExecuteBatchTriage && (
            canExecuteBatchTriage ? (
            <button
              type="button"
              disabled={isExecutingBatch}
              onClick={() => void handleRunBatchTriage()}
              className="cursor-pointer disabled:opacity-60 w-full py-2 px-3 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs flex items-center justify-center gap-1.5 transition-colors"
            >
              <Zap className="w-3.5 h-3.5" />
              <span>
                {isExecutingBatch
                  ? 'Đang khóa cụm & Auto-Clear...'
                  : 'Thực thi Gom nhóm 1-Chạm (Khóa cụm & Đóng ca an toàn)'}
              </span>
            </button>
            ) : (
              <div className="p-2 rounded-lg bg-slate-900 border border-slate-700 text-[11px] text-amber-300 font-semibold">
                Chỉ Quản lý Rủi ro L2 (Checker) mới được thực thi Gom nhóm 1-Chạm.
              </div>
            )
          )}
        </div>
      )}

      {/* Clean Case Builder Button */}
      <button
        type="button"
        onClick={onOpenSandbox}
        className="cursor-pointer w-full py-2.5 px-3.5 rounded-xl bg-violet-600/20 hover:bg-violet-600/30 border border-violet-500/40 flex items-center justify-between text-left transition-colors shrink-0"
      >
        <div className="flex items-center gap-2.5">
          <FlaskConical className="w-4 h-4 text-violet-300 shrink-0" />
          <div>
            <div className="text-xs font-bold text-white">
              + Nhập Hồ sơ &amp; Dữ liệu Kiểm thử Mới
            </div>
            <div className="text-[11px] text-slate-300">
              Biểu mẫu Chuẩn 4 Phần • Tự nhập dữ liệu hoặc quét ảnh OCR
            </div>
          </div>
        </div>
        <PlusCircle className="w-4 h-4 text-amber-400 shrink-0" />
      </button>

      {/* Alert Cards */}
      <div className="flex flex-col gap-2.5 overflow-y-auto pr-1 flex-1 min-h-0">
        {alerts.map((alert, index) => {
          const isSelected = alert.id === selectedAlertId;
          const badge = SCENARIO_BADGE[alert.scenarioCode];
          const isMitigated = alert.status === 'MITIGATED';
          const isSafeDismissed = alert.status === 'DISMISSED_SAFE';
          const corr = triageSummary.correlationsByAlertId[alert.id];
          const liveScore =
            forensicsMap[alert.id]?.deterministicRiskScore ?? alert.deterministicRiskScore;

          return (
            <button
              key={alert.id}
              type="button"
              onClick={() => onSelectAlert(alert.id)}
              className={`cursor-pointer text-left p-3.5 rounded-xl border transition-all duration-200 ${
                isSelected
                  ? 'bg-slate-800/95 border-amber-400 ring-1 ring-amber-400/30 shadow-md'
                  : 'bg-slate-950/70 border-slate-800 hover:bg-slate-800/50 hover:border-slate-700'
              }`}
            >
              <div className="flex items-center justify-between gap-2 mb-1.5">
                <span className="text-xs font-bold text-amber-400">
                  Vụ #{index + 1} ({alert.id})
                </span>
                <span
                  className={`text-xs font-bold px-2 py-0.5 rounded-md ${
                    liveScore >= 80
                      ? 'bg-red-500/20 text-red-300 border border-red-500/30'
                      : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                  }`}
                >
                  Rủi ro: {liveScore}/100
                </span>
              </div>

              <div className="mb-2 flex flex-wrap items-center gap-1.5">
                <span className={`inline-block text-xs font-semibold px-2 py-0.5 rounded-md border ${badge.color}`}>
                  {badge.label}
                </span>
                {corr && corr.linkedAlertIds.length > 0 && (
                  <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-xs font-semibold bg-slate-900 text-amber-200 border border-slate-700">
                    <Link2 className="w-3 h-3 text-amber-400" />
                    Chung máy {corr.sharedInfrastructureIds[0]}
                  </span>
                )}
                {isMitigated && (
                  <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-xs font-semibold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                    <Lock className="w-3 h-3" />
                    Đã bật Lá chắn
                  </span>
                )}
                {isSafeDismissed && (
                  <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-xs font-semibold bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">
                    <UserCheck className="w-3 h-3" />
                    An toàn
                  </span>
                )}
              </div>

              <h3 className="text-sm font-bold text-white leading-snug mb-1">{alert.title}</h3>
              <p className="text-xs text-slate-300 leading-relaxed">{alert.subtitle}</p>

              <div className="mt-2 pt-2 border-t border-slate-800/80 flex items-center justify-between text-xs text-slate-400">
                <span>
                  TK nhận: <strong className="text-slate-200">{alert.targetRecipientAccountId}</strong>
                </span>
                {isMitigated || isSafeDismissed ? (
                  <span className="text-emerald-400 font-bold flex items-center gap-1">
                    <CheckCircle2 className="w-3.5 h-3.5" /> Đã xử lý
                  </span>
                ) : (
                  <span className="text-amber-400 font-bold flex items-center gap-1">
                    <AlertTriangle className="w-3.5 h-3.5" /> Cần duyệt
                  </span>
                )}
              </div>
            </button>
          );
        })}
      </div>
    </aside>
  );
};
