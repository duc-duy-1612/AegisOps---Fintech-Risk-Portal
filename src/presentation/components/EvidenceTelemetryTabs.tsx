'use client';

import { useEffect, useMemo, useState } from 'react';
import {
  Activity,
  FileImage,
  History,
  KeyRound,
  Maximize2,
  RefreshCw,
  ShieldCheck,
  SlidersHorizontal,
  X,
} from 'lucide-react';
import { evaluateLiveCaseInputPreview } from '@/domain/sandbox-synthesizer';
import { inspectMaliciousUrlsAndApks } from '@/domain/forensics-analyzers';
import type {
  ApiSecurityEvent,
  AuditLogEntry,
  AuthSessionLog,
  EvidenceArtifact,
  StandardCaseInputSpec,
  Transaction,
  UrlThreatFinding,
} from '@/domain/types';

interface EvidenceTelemetryTabsProps {
  alertId: string;
  primaryAccountId: string;
  inputSpec: StandardCaseInputSpec | null;
  evidences: EvidenceArtifact[];
  authLogs: AuthSessionLog[];
  transactions: Transaction[];
  apiEvents: ApiSecurityEvent[];
  auditLogs: AuditLogEntry[];
  highlightedEvidenceId: string | null;
  compactMode?: boolean;
  isApplyingWhatIf?: boolean;
  onEditCaseSpec: (spec: StandardCaseInputSpec) => void;
  onQuickApplyWhatIf?: (spec: StandardCaseInputSpec) => Promise<boolean>;
}

type TabKey = 'MULTIMODAL' | 'INPUT_SPEC' | 'LEDGER_API' | 'AUTH_LOGS' | 'AUDIT';

export const EvidenceTelemetryTabs = ({
  alertId,
  primaryAccountId,
  inputSpec,
  evidences,
  authLogs,
  transactions,
  apiEvents,
  auditLogs,
  highlightedEvidenceId,
  compactMode = false,
  isApplyingWhatIf = false,
  onEditCaseSpec,
  onQuickApplyWhatIf,
}: EvidenceTelemetryTabsProps) => {
  const [activeTab, setActiveTab] = useState<TabKey>('MULTIMODAL');
  const [zoomedImage, setZoomedImage] = useState<{ url: string; title: string } | null>(null);
  const [whatIfSpec, setWhatIfSpec] = useState<StandardCaseInputSpec | null>(inputSpec);

  useEffect(() => {
    setWhatIfSpec(inputSpec);
  }, [inputSpec, alertId]);

  const whatIfPreview = useMemo(
    () => (whatIfSpec ? evaluateLiveCaseInputPreview(whatIfSpec) : null),
    [whatIfSpec]
  );

  const alertEvidences = evidences.filter((e) => e.alertId === alertId);
  const urlFindings: UrlThreatFinding[] = useMemo(
    () => inspectMaliciousUrlsAndApks(alertEvidences.map((e) => `${e.title} ${e.textContent}`).join(' ')),
    [alertEvidences]
  );
  const alertAuthLogs = authLogs.filter((l) => l.accountId === primaryAccountId);
  const alertTxs = transactions.filter((t) => t.alertId === alertId);
  const alertApiEvents = apiEvents.filter((e) => e.alertId === alertId);

  useEffect(() => {
    if (!highlightedEvidenceId) return;
    if (highlightedEvidenceId.startsWith('EVD-')) {
      setActiveTab('MULTIMODAL');
    } else if (highlightedEvidenceId.startsWith('LOG-')) {
      setActiveTab('AUTH_LOGS');
    } else if (
      highlightedEvidenceId.startsWith('TXN-') ||
      highlightedEvidenceId.startsWith('EVT-')
    ) {
      setActiveTab('LEDGER_API');
    }
  }, [highlightedEvidenceId]);

  const highlightClass = (id: string) =>
    highlightedEvidenceId === id
      ? 'border-amber-400 bg-amber-500/15 ring-2 ring-amber-400/50'
      : 'border-slate-800 bg-slate-950/80';

  return (
    <section className="bg-slate-900/90 border border-slate-800 rounded-2xl p-4 flex flex-col gap-3 shadow-lg flex-1 min-h-0">
      {/* Unified Section Title matching MoneyFlowGraphCanvas */}
      <div className="flex flex-wrap items-center justify-between gap-2 shrink-0">
        <div className="flex items-center gap-2">
          <FileImage className="w-4 h-4 text-amber-400" />
          <h2 className="text-sm font-bold text-white">
            Chi tiết Bằng chứng, Thông số Đầu vào &amp; Nhật ký ({alertId})
          </h2>
        </div>

        <div className="flex items-center gap-2">
          {highlightedEvidenceId && (
            <span className="text-xs font-semibold px-2.5 py-0.5 rounded-lg bg-amber-500/20 text-amber-300 border border-amber-500/40">
              Đang trỏ: <strong>{highlightedEvidenceId}</strong>
            </span>
          )}
          {inputSpec && (
            <button
              type="button"
              onClick={() => onEditCaseSpec(inputSpec)}
              className="cursor-pointer inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-bold bg-violet-600/25 hover:bg-violet-600/40 text-violet-200 border border-violet-500/40 transition-colors"
            >
              <SlidersHorizontal className="w-3.5 h-3.5" />
              <span>Tùy chỉnh Thông số Vụ này</span>
            </button>
          )}
        </div>
      </div>

      {/* Clean Tab Navigation */}
      <div className="flex flex-wrap items-center gap-1.5 border-b border-slate-800 pb-2 shrink-0">
        <button
          type="button"
          onClick={() => setActiveTab('MULTIMODAL')}
          className={`cursor-pointer px-2.5 py-1 rounded-xl text-xs font-bold flex items-center gap-1.5 transition-colors ${
            activeTab === 'MULTIMODAL'
              ? 'bg-amber-500 text-slate-950 shadow'
              : 'bg-slate-950/70 text-slate-300 hover:text-white border border-slate-800'
          }`}
        >
          <FileImage className="w-3.5 h-3.5" />
          <span>Bằng chứng Ảnh / Chat ({alertEvidences.length})</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('INPUT_SPEC')}
          className={`cursor-pointer px-2.5 py-1 rounded-xl text-xs font-bold flex items-center gap-1.5 transition-colors ${
            activeTab === 'INPUT_SPEC'
              ? 'bg-violet-500 text-white shadow'
              : 'bg-slate-950/70 text-slate-300 hover:text-white border border-slate-800'
          }`}
        >
          <SlidersHorizontal className="w-3.5 h-3.5" />
          <span>Hồ sơ Đầu vào (4 Phần)</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('LEDGER_API')}
          className={`cursor-pointer px-2.5 py-1 rounded-xl text-xs font-bold flex items-center gap-1.5 transition-colors ${
            activeTab === 'LEDGER_API'
              ? 'bg-amber-500 text-slate-950 shadow'
              : 'bg-slate-950/70 text-slate-300 hover:text-white border border-slate-800'
          }`}
        >
          <Activity className="w-3.5 h-3.5" />
          <span>Giao dịch &amp; API ({alertTxs.length + alertApiEvents.length})</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('AUTH_LOGS')}
          className={`cursor-pointer px-2.5 py-1 rounded-xl text-xs font-bold flex items-center gap-1.5 transition-colors ${
            activeTab === 'AUTH_LOGS'
              ? 'bg-amber-500 text-slate-950 shadow'
              : 'bg-slate-950/70 text-slate-300 hover:text-white border border-slate-800'
          }`}
        >
          <KeyRound className="w-3.5 h-3.5" />
          <span>Phiên Đăng nhập ({alertAuthLogs.length})</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('AUDIT')}
          className={`cursor-pointer px-2.5 py-1 rounded-xl text-xs font-bold flex items-center gap-1.5 transition-colors ${
            activeTab === 'AUDIT'
              ? 'bg-emerald-500 text-slate-950 shadow'
              : 'bg-slate-950/70 text-slate-300 hover:text-white border border-slate-800'
          }`}
        >
          <History className="w-3.5 h-3.5" />
          <span>Nhật ký ({auditLogs.length})</span>
        </button>
      </div>

      {/* Scrollable Tab Body */}
      <div className="space-y-2.5 overflow-y-auto flex-1 pr-1 min-h-0">
        {activeTab === 'MULTIMODAL' && (
          <div className="space-y-2.5">
            {urlFindings.length > 0 && (
              <div className="p-3 rounded-xl border border-rose-500/40 bg-rose-950/30 space-y-1.5 text-xs">
                <div className="font-bold text-rose-300 flex items-center justify-between gap-2">
                  <span>Bộ giải phẫu Link Phishing, Tên miền Giả mạo &amp; Tệp .APK ({urlFindings.length})</span>
                  <span className="px-2 py-0.5 rounded bg-rose-500/20 text-rose-200 border border-rose-500/30">
                    Cyber Threat Intel
                  </span>
                </div>
                {urlFindings.map((uf) => (
                  <div
                    key={uf.url}
                    className="p-2 rounded-lg bg-slate-950/90 border border-slate-800 space-y-0.5"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <code className="text-amber-300 font-bold break-all">{uf.url}</code>
                      <span
                        className={`px-2 py-0.5 rounded font-bold text-[10px] ${
                          uf.verdict === 'SAFE_OFFICIAL'
                            ? 'bg-emerald-500/20 text-emerald-300'
                            : 'bg-red-500/25 text-red-200'
                        }`}
                      >
                        Rủi ro URL: {uf.riskScore}/100 {uf.isApkPayload ? '• APK Độc hại' : ''}
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-300">{uf.reasonVi}</div>
                  </div>
                ))}
              </div>
            )}
            {alertEvidences.map((ev) => (
            <div
              key={ev.id}
              className={`p-3 rounded-xl border transition-all duration-200 ${highlightClass(ev.id)}`}
            >
              <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-bold px-2 py-0.5 rounded-md bg-amber-500/20 text-amber-300 border border-amber-500/30">
                    {ev.id}
                  </span>
                  <h3 className="text-xs font-bold text-white">{ev.title}</h3>
                </div>
                {ev.imageDataUrl && (
                  <button
                    type="button"
                    onClick={() => setZoomedImage({ url: ev.imageDataUrl!, title: ev.title })}
                    className="cursor-pointer inline-flex items-center gap-1 px-2 py-0.5 rounded-lg text-xs font-bold bg-slate-800 hover:bg-slate-700 text-amber-300 border border-slate-700"
                  >
                    <Maximize2 className="w-3 h-3" />
                    <span>Phóng to ảnh</span>
                  </button>
                )}
              </div>

              <div className={compactMode ? 'space-y-2.5' : 'grid grid-cols-1 xl:grid-cols-12 gap-3 items-start'}>
                {ev.imageDataUrl && (
                  <div className={compactMode ? '' : 'xl:col-span-5'}>
                    {/* eslint-disable-next-line @next/next/no-img-element */}
                    <img
                      src={ev.imageDataUrl}
                      alt={ev.title}
                      onClick={() => setZoomedImage({ url: ev.imageDataUrl!, title: ev.title })}
                      className="cursor-pointer w-full rounded-xl border border-slate-700 hover:border-amber-400 object-contain max-h-40 bg-slate-950 transition-colors"
                    />
                  </div>
                )}
                <div className={compactMode ? '' : ev.imageDataUrl ? 'xl:col-span-7' : 'xl:col-span-12'}>
                  <p className="text-xs text-slate-100 bg-slate-900 p-2.5 rounded-xl border border-slate-800 leading-relaxed">
                    {ev.textContent}
                  </p>
                  <div className="flex flex-wrap gap-1.5 mt-2">
                    {ev.extractedSignals.map((sig, idx) => (
                      <span
                        key={idx}
                        className="text-[11px] font-semibold px-2 py-0.5 rounded-lg bg-red-500/15 text-red-200 border border-red-500/30"
                      >
                        • {sig}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            </div>
            ))}
          </div>
        )}

        {/* NEW TAB: Standardized 4-Part Case Input Specification + Inline What-If Simulation */}
        {activeTab === 'INPUT_SPEC' && whatIfSpec && whatIfPreview && (
          <div className="bg-slate-950/90 border border-slate-800 rounded-xl p-3 space-y-3 text-xs">
            <div className="flex flex-wrap items-center justify-between gap-2 pb-2 border-b border-slate-800">
              <div>
                <div className="font-bold text-white flex items-center gap-2">
                  <span>Phân tích &ldquo;What-If&rdquo; Trực tiếp ({alertId})</span>
                  <span
                    className={`px-2 py-0.5 rounded-md text-[11px] font-bold border ${
                      whatIfPreview.riskScore >= 80
                        ? 'bg-red-500/20 text-red-200 border-red-500/40'
                        : whatIfPreview.riskScore < 30
                          ? 'bg-emerald-500/20 text-emerald-200 border-emerald-500/40'
                          : 'bg-amber-500/20 text-amber-200 border-amber-500/40'
                    }`}
                  >
                    Dự báo mới: {whatIfPreview.riskScore}/100
                  </span>
                </div>
                <div className="text-[11px] text-slate-400">
                  Thay đổi trực tiếp thông số bên dưới để xem điểm Z-Score &amp; rủi ro biến động tức thời
                </div>
              </div>
              <div className="flex items-center gap-1.5">
                <button
                  type="button"
                  onClick={() => onEditCaseSpec(whatIfSpec)}
                  className="cursor-pointer inline-flex items-center gap-1 px-2.5 py-1.5 rounded-xl bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700 font-bold"
                >
                  <SlidersHorizontal className="w-3.5 h-3.5 text-violet-400" />
                  <span>Mở Form Đầy đủ</span>
                </button>
                {onQuickApplyWhatIf && (
                  <button
                    type="button"
                    disabled={isApplyingWhatIf}
                    onClick={() => void onQuickApplyWhatIf(whatIfSpec)}
                    className="cursor-pointer inline-flex items-center gap-1 px-3 py-1.5 rounded-xl bg-amber-500 hover:bg-amber-400 text-slate-950 font-bold"
                  >
                    <RefreshCw className={`w-3.5 h-3.5 ${isApplyingWhatIf ? 'animate-spin' : ''}`} />
                    <span>{isApplyingWhatIf ? 'Đang chạy...' : 'Áp dụng & Tính lại'}</span>
                  </button>
                )}
              </div>
            </div>

            {/* Inline Editable What-If Controls */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
              <div className="bg-slate-900 p-2.5 rounded-lg border border-slate-800 space-y-2">
                <div className="font-bold text-cyan-300">1. Giao dịch &amp; Chia nhỏ tiền</div>
                <div>
                  <label className="block text-[11px] text-slate-400 mb-0.5">
                    Số tiền (VNĐ) • Z-Score dự báo: <strong className="text-amber-300">+{whatIfPreview.zScoreDeviation}σ</strong>
                  </label>
                  <input
                    type="number"
                    step={500000}
                    value={whatIfSpec.amountVnd}
                    onChange={(e) =>
                      setWhatIfSpec((prev) =>
                        prev ? { ...prev, amountVnd: Math.max(10000, Number(e.target.value) || 0) } : prev
                      )
                    }
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg px-2 py-1 text-amber-300 font-bold"
                  />
                </div>
                <div>
                  <label className="block text-[11px] text-slate-400 mb-0.5">
                    Số lệnh chia nhỏ (Smurfing Entropy: <strong className="text-cyan-300">{whatIfPreview.smurfingEntropyIndex}</strong>)
                  </label>
                  <select
                    value={whatIfSpec.splitTxCount}
                    onChange={(e) =>
                      setWhatIfSpec((prev) =>
                        prev ? { ...prev, splitTxCount: Number(e.target.value) } : prev
                      )
                    }
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg px-2 py-1 text-white"
                  >
                    <option value={1}>1 lệnh đơn lẻ</option>
                    <option value={2}>2 lệnh liên tiếp</option>
                    <option value={3}>3 lệnh chia nhỏ (Smurfing)</option>
                  </select>
                </div>
              </div>

              <div className="bg-slate-900 p-2.5 rounded-lg border border-slate-800 space-y-2">
                <div className="font-bold text-amber-300">2. Người nhận &amp; Hành vi QĐ 2345</div>
                <div>
                  <label className="block text-[11px] text-slate-400 mb-0.5">
                    Loại tài khoản nhận ({whatIfSpec.recipientAccountNumber})
                  </label>
                  <select
                    value={whatIfSpec.recipientAccountType}
                    onChange={(e) =>
                      setWhatIfSpec((prev) =>
                        prev
                          ? {
                              ...prev,
                              recipientAccountType: e.target
                                .value as StandardCaseInputSpec['recipientAccountType'],
                            }
                          : prev
                      )
                    }
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg px-2 py-1 text-white"
                  >
                    <option value="MULE_SUSPECT">TK Cá nhân mới / Nghi vấn Mule</option>
                    <option value="CONSUMER">Cá nhân bình thường</option>
                    <option value="TRUSTED_INSTITUTION">Bệnh viện / Đối tác Uy tín (-22đ)</option>
                  </select>
                </div>

                <label className="flex items-center justify-between gap-2 bg-slate-950 px-2.5 py-1.5 rounded-lg border border-slate-800 cursor-pointer">
                  <span className="text-[11px] font-semibold text-slate-200">
                    Đang nghe cuộc gọi lạ + Paste STK (In-Call)
                  </span>
                  <input
                    type="checkbox"
                    checked={whatIfSpec.inCallCoercionDetected}
                    onChange={(e) =>
                      setWhatIfSpec((prev) =>
                        prev ? { ...prev, inCallCoercionDetected: e.target.checked } : prev
                      )
                    }
                    className="h-4 w-4 accent-amber-500"
                  />
                </label>

                <label className="flex items-center justify-between gap-2 bg-slate-950 px-2.5 py-1.5 rounded-lg border border-rose-500/30 cursor-pointer">
                  <span className="text-[11px] font-semibold text-rose-200">
                    Phát hiện Deepfake / Camera Ảo (ISO 30107-3)
                  </span>
                  <input
                    type="checkbox"
                    checked={Boolean(whatIfSpec.deepfakeOrVirtualCamDetected)}
                    onChange={(e) =>
                      setWhatIfSpec((prev) =>
                        prev ? { ...prev, deepfakeOrVirtualCamDetected: e.target.checked } : prev
                      )
                    }
                    className="h-4 w-4 accent-rose-500"
                  />
                </label>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'LEDGER_API' && (
          <div className="space-y-2">
            {alertTxs.map((tx) => (
              <div
                key={tx.id}
                className={`p-3 rounded-xl border text-xs ${highlightClass(tx.id)}`}
              >
                <div className="flex flex-wrap items-center justify-between gap-2 mb-1">
                  <span className="font-bold text-amber-300">
                    Giao dịch {tx.id} • {tx.amountVnd.toLocaleString('vi-VN')} ₫
                  </span>
                  <span className="text-slate-200 font-semibold">
                    Từ <strong>{tx.senderAccountId}</strong> → Nhận:{' '}
                    <strong className="text-red-300">{tx.receiverAccountId}</strong>
                  </span>
                </div>
                <p className="text-slate-300 text-xs">
                  Kênh: <strong>{tx.channel}</strong> • Thiết bị: <strong className="text-cyan-300">{tx.deviceId}</strong> • Nội dung: &ldquo;{tx.message}&rdquo;
                </p>
              </div>
            ))}
            {alertApiEvents.map((evt) => (
              <div
                key={evt.id}
                className={`p-3 rounded-xl border text-xs ${highlightClass(evt.id)}`}
              >
                <div className="flex flex-wrap items-center justify-between gap-2 mb-1">
                  <span className="font-bold text-violet-300">
                    Sự kiện API {evt.id} ({evt.endpoint})
                  </span>
                  <span className="text-red-300 font-bold">
                    {evt.concurrentRequests100ms} request/100ms • Chữ ký HMAC:{' '}
                    {evt.hmacSignatureValid ? 'Hợp lệ' : 'Giả mạo'}
                  </span>
                </div>
                <p className="text-slate-200 text-xs">{evt.payloadSummary}</p>
              </div>
            ))}
          </div>
        )}

        {activeTab === 'AUTH_LOGS' &&
          alertAuthLogs.map((log) => (
            <div
              key={log.id}
              className={`p-3 rounded-xl border text-xs transition-all ${highlightClass(log.id)}`}
            >
              <div className="flex flex-wrap items-center justify-between gap-2 mb-1">
                <span className="font-bold text-cyan-300">
                  {log.id} • {log.eventType}
                </span>
                <span className="text-slate-300 font-semibold">
                  Thiết bị: <strong className="text-white">{log.deviceId}</strong> • IP {log.ipAddress} ({log.location})
                </span>
              </div>
              <p className="text-slate-100 text-xs leading-relaxed">{log.summary}</p>
            </div>
          ))}

        {activeTab === 'AUDIT' &&
          auditLogs
            .slice()
            .reverse()
            .map((aud) => (
              <div
                key={aud.id}
                className="p-2.5 rounded-xl border border-slate-800 bg-slate-950/80 text-xs flex items-start justify-between gap-3"
              >
                <div className="flex items-start gap-2">
                  <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                  <div>
                    <div className="font-bold text-emerald-300">
                      [{aud.actor}] {aud.action} ({aud.alertId})
                    </div>
                    <div className="text-slate-200 text-xs mt-0.5">{aud.detailsVi}</div>
                  </div>
                </div>
                <span suppressHydrationWarning className="text-xs text-slate-400 shrink-0">
                  {new Date(aud.timestamp).toLocaleTimeString('vi-VN')}
                </span>
              </div>
            ))}
      </div>

      {zoomedImage && (
        <div
          onClick={() => setZoomedImage(null)}
          className="fixed inset-0 z-50 bg-slate-950/85 backdrop-blur-sm flex items-center justify-center p-4"
        >
          <div
            onClick={(e) => e.stopPropagation()}
            className="max-w-3xl w-full bg-slate-900 border border-slate-700 rounded-2xl p-4 space-y-3 shadow-2xl"
          >
            <div className="flex items-center justify-between">
              <h4 className="text-sm font-bold text-white">{zoomedImage.title}</h4>
              <button
                type="button"
                onClick={() => setZoomedImage(null)}
                className="cursor-pointer p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img
              src={zoomedImage.url}
              alt={zoomedImage.title}
              className="w-full rounded-xl border border-slate-800 bg-slate-950 max-h-[75vh] object-contain"
            />
          </div>
        </div>
      )}
    </section>
  );
};
