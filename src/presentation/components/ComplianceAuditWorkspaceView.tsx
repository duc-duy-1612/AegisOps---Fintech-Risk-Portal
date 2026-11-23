'use client';

import { useMemo, useState } from 'react';
import { CheckCircle2, FileCheck2, History, Printer, Send, ShieldCheck } from 'lucide-react';
import {
  buildComplianceIncidentDossier,
  type ComplianceIncidentDossier,
} from '@/domain/compliance-report';
import type {
  Account,
  AuditLogEntry,
  AuthSessionLog,
  DeviceFingerprint,
  ForensicSuiteOutput,
  FraudAlert,
  InvestigationReport,
  SimoReceiptRecord,
  Transaction,
} from '@/domain/types';
import { ComplianceReportModal } from './ComplianceReportModal';

interface ComplianceAuditWorkspaceViewProps {
  alerts: FraudAlert[];
  forensicsMap: Record<string, ForensicSuiteOutput>;
  reportsByAlertId: Record<string, InvestigationReport>;
  accounts?: Account[];
  transactions?: Transaction[];
  authLogs?: AuthSessionLog[];
  devices?: DeviceFingerprint[];
  auditLogs: AuditLogEntry[];
  simoAckReceipts?: SimoReceiptRecord[];
  canPushToSimo?: boolean;
  onPushToSimo?: (alertId: string) => Promise<SimoReceiptRecord | null>;
}

export const ComplianceAuditWorkspaceView = ({
  alerts,
  forensicsMap,
  reportsByAlertId,
  accounts = [],
  transactions = [],
  authLogs = [],
  devices = [],
  auditLogs,
  simoAckReceipts = [],
  canPushToSimo = true,
  onPushToSimo,
}: ComplianceAuditWorkspaceViewProps) => {
  const [selectedDossierAlertId, setSelectedDossierAlertId] = useState<string>(
    alerts[0]?.id ?? 'ALT-APP-003'
  );
  const [actorTagFilter, setActorTagFilter] = useState<
    'ALL' | AuditLogEntry['actor']
  >('ALL');
  const [modalDossier, setModalDossier] = useState<ComplianceIncidentDossier | null>(null);
  const [isPushingSimo, setIsPushingSimo] = useState(false);

  const selectedAlert = alerts.find((a) => a.id === selectedDossierAlertId) ?? alerts[0];
  const activeForensics = selectedAlert ? forensicsMap[selectedAlert.id] : undefined;
  const activeReceipt = selectedAlert
    ? simoAckReceipts.find((r) => r.alertId === selectedAlert.id)
    : undefined;

  const previewDossier = useMemo(() => {
    if (!selectedAlert || !activeForensics) return null;
    return buildComplianceIncidentDossier({
      alert: selectedAlert,
      forensics: activeForensics,
      report: reportsByAlertId[selectedAlert.id] ?? null,
      auditLogs,
      accounts,
      transactions,
      authLogs,
      devices,
    });
  }, [accounts, activeForensics, auditLogs, authLogs, devices, reportsByAlertId, selectedAlert, transactions]);

  const filteredLogs = auditLogs
    .filter((l) => (actorTagFilter === 'ALL' ? true : l.actor === actorTagFilter))
    .slice()
    .reverse();

  return (
    <div className="grid grid-cols-1 xl:grid-cols-12 gap-4 items-start">
      {/* Left: SBV Compliance Dossier & 1-Click Push to SIMO Registry */}
      <section className="xl:col-span-7 bg-slate-900/90 border border-slate-800 rounded-2xl p-4 space-y-3 shadow-lg">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <FileCheck2 className="w-4 h-4 text-emerald-400" />
            <h2 className="text-sm font-bold text-white">
              Hồ sơ Pháp lý NHNN &amp; Cổng Đồng bộ SIMO Ẩn danh PII
            </h2>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <select
              value={selectedDossierAlertId}
              onChange={(e) => setSelectedDossierAlertId(e.target.value)}
              className="bg-slate-950 border border-slate-700 rounded-xl px-3 py-1.5 text-xs font-bold text-white"
            >
              {alerts.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.id} — {a.title.slice(0, 42)}
                </option>
              ))}
            </select>

            {previewDossier && (
              <button
                type="button"
                onClick={() => setModalDossier(previewDossier)}
                className="cursor-pointer inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-amber-500 hover:bg-amber-400 text-slate-950 text-xs font-bold"
              >
                <Printer className="w-3.5 h-3.5" />
                <span>Mở &amp; Xuất PDF</span>
              </button>
            )}

            {onPushToSimo && selectedAlert && canPushToSimo && (
              <button
                type="button"
                disabled={isPushingSimo}
                onClick={async () => {
                  setIsPushingSimo(true);
                  try {
                    await onPushToSimo(selectedAlert.id);
                  } finally {
                    setIsPushingSimo(false);
                  }
                }}
                className="cursor-pointer inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-emerald-500 hover:bg-emerald-400 text-slate-950 text-xs font-bold"
              >
                <Send className="w-3.5 h-3.5" />
                <span>
                  {activeReceipt
                    ? `Đã tạo biên nhận SIMO mô phỏng (${activeReceipt.receiptId})`
                    : isPushingSimo
                      ? 'Đang tạo bản tin SIMO mô phỏng...'
                      : 'Gửi bản tin SIMO (Mô phỏng)'}
                </span>
              </button>
            )}
          </div>
        </div>

        {activeReceipt && (
          <div className="p-3 rounded-xl bg-emerald-950/60 border border-emerald-500/50 text-xs flex flex-wrap items-center justify-between gap-2 text-emerald-100">
            <span className="flex items-center gap-1.5 font-bold">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              <span>Đã tạo biên nhận đồng bộ SIMO cục bộ (SIMULATED — Chưa kết nối mạng NHNN/A05 thực tế)</span>
            </span>
            <span className="px-2 py-0.5 rounded bg-black/40 font-bold text-amber-300">
              Mã biên nhận mô phỏng: {activeReceipt.receiptId}
            </span>
          </div>
        )}

        {previewDossier && (
          <div className="space-y-3 text-xs">
            <div className="bg-slate-950 border border-slate-800 rounded-xl p-3.5 space-y-1.5">
              <div className="font-bold text-amber-300">
                Kết luận Hồ sơ ({previewDossier.dossierId}) • Điểm định lượng:{' '}
                {previewDossier.deterministicRiskScore}/100
              </div>
              <p className="text-slate-200 leading-relaxed">
                {previewDossier.executiveSummaryVi}
              </p>
            </div>

            <div className="bg-slate-950 border border-violet-500/30 rounded-xl p-3.5 space-y-2">
              <div className="font-bold text-violet-300">
                Đối chiếu Pháp lý (QĐ 2345/QĐ-NHNN • TT 50/2024 sửa đổi bởi TT 77/2025 • Luật 91/2025/QH15 &amp; NĐ 356/2025/NĐ-CP)
              </div>
              <ul className="space-y-1 text-slate-200">
                {previewDossier.regulatoryReferencesVi.map((r, i) => (
                  <li key={i} className="flex items-start gap-2">
                    <span className="text-amber-400 font-bold">•</span>
                    <span>{r}</span>
                  </li>
                ))}
              </ul>
            </div>

            <div className="bg-slate-950 border border-slate-800 rounded-xl p-3.5 space-y-1.5">
              <div className="font-bold text-emerald-300">
                Bản tin Đồng bộ SIMO Mô phỏng (SHA-256 Digest Preview / Server HMAC-SHA-256 Pseudonymization — KHÔNG phải ẩn danh hóa):
              </div>
              <pre className="bg-slate-900 p-3 rounded-lg border border-slate-800 text-[11px] text-emerald-300 overflow-x-auto">
                {JSON.stringify(previewDossier.simoPiiMaskedPayload, null, 2)}
              </pre>
            </div>

            {simoAckReceipts.length > 0 && (
              <div className="bg-slate-950 border border-slate-800 rounded-xl p-3.5 space-y-2">
                <div className="font-bold text-cyan-300">
                  Biên nhận Đã Đồng bộ SIMO ({simoAckReceipts.length} hồ sơ)
                </div>
                <div className="space-y-1.5">
                  {simoAckReceipts.map((r) => (
                    <div
                      key={r.receiptId}
                      className="flex flex-wrap items-center justify-between gap-2 p-2 rounded-lg bg-slate-900 border border-slate-800"
                    >
                      <span className="font-bold text-white">
                        {r.receiptId} • {r.alertId} ({r.complianceStandard})
                      </span>
                      <span className="text-[11px] text-emerald-300">{r.victimIdentityHashSha256}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </section>

      {/* Right: Filterable System Audit Trail with Actor Tags */}
      <section className="xl:col-span-5 bg-slate-900/90 border border-slate-800 rounded-2xl p-4 space-y-3 shadow-lg">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <History className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-bold text-white">
              Nhật ký Kiểm toán Hệ thống ({filteredLogs.length})
            </h2>
          </div>
        </div>

        {/* Actor Tag Filter Box */}
        <div className="flex flex-wrap items-center gap-1.5">
          {(
            [
              { id: 'ALL', label: 'Tất cả' },
              { id: 'AI_AGENT', label: 'AI Agent' },
              { id: 'OPS_ANALYST', label: 'Chuyên viên' },
              { id: 'CONSUMER_SHIELD', label: 'Lá chắn Ví' },
            ] as const
          ).map((tag) => (
            <button
              key={tag.id}
              type="button"
              onClick={() => setActorTagFilter(tag.id)}
              className={`cursor-pointer px-2.5 py-1 rounded-lg text-[11px] font-bold border transition-colors ${actorTagFilter === tag.id
                ? 'bg-amber-500 text-slate-950 border-amber-400'
                : 'bg-slate-950 text-slate-300 border-slate-800 hover:text-white'
                }`}
            >
              {tag.label}
            </button>
          ))}
        </div>

        <div className="space-y-2 max-h-[540px] overflow-y-auto pr-1">
          {filteredLogs.map((aud) => (
            <div
              key={aud.id}
              className="p-3 rounded-xl bg-slate-950 border border-slate-800 text-xs flex items-start justify-between gap-2.5"
            >
              <div className="flex items-start gap-2">
                <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                <div>
                  <div className="font-bold text-emerald-300">
                    [{aud.actor}] {aud.action} • {aud.alertId}
                  </div>
                  <p className="text-slate-200 mt-0.5 leading-relaxed">{aud.detailsVi}</p>
                </div>
              </div>
              <span suppressHydrationWarning className="text-[11px] text-slate-400 shrink-0">
                {new Date(aud.timestamp).toLocaleTimeString('vi-VN')}
              </span>
            </div>
          ))}
        </div>
      </section>

      <ComplianceReportModal
        dossier={modalDossier}
        onClose={() => setModalDossier(null)}
      />
    </div>
  );
};
