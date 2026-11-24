'use client';

import { useEffect, useRef, useState } from 'react';
import {
  Check,
  Copy,
  FileCheck2,
  Printer,
  ShieldCheck,
  X,
} from 'lucide-react';
import type { ComplianceIncidentDossier } from '@/domain/compliance-report';

interface ComplianceReportModalProps {
  dossier: ComplianceIncidentDossier | null;
  onClose: () => void;
}

export const ComplianceReportModal = ({
  dossier,
  onClose,
}: ComplianceReportModalProps) => {
  const [copied, setCopied] = useState(false);
  const copyTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    return () => {
      if (copyTimerRef.current) {
        clearTimeout(copyTimerRef.current);
        copyTimerRef.current = null;
      }
    };
  }, []);

  if (!dossier) return null;

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(dossier.markdownText);
      setCopied(true);
      if (copyTimerRef.current) clearTimeout(copyTimerRef.current);
      copyTimerRef.current = setTimeout(() => {
        setCopied(false);
        copyTimerRef.current = null;
      }, 2000);
    } catch {
      // Ignore clipboard permission errors
    }
  };

  return (
    <div
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      aria-labelledby="compliance-dossier-title"
      className="printable-dossier-overlay fixed inset-0 z-50 bg-slate-950/85 backdrop-blur-sm flex items-center justify-center p-4"
    >
      <div
        onClick={(e) => e.stopPropagation()}
        className="printable-dossier-card w-full max-w-3xl bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]"
      >
        {/* Header */}
        <div className="px-5 py-4 bg-slate-950 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2.5">
            <div className="no-print h-9 w-9 rounded-xl bg-emerald-500/20 border border-emerald-500/40 flex items-center justify-center text-emerald-300">
              <FileCheck2 className="w-5 h-5" />
            </div>
            <div>
              <h2 id="compliance-dossier-title" className="text-sm font-bold text-white">
                Biên bản Điều tra &amp; Hồ sơ Tuân thủ An ninh Fintech ({dossier.dossierId})
              </h2>
              <p className="text-xs text-slate-400">
                Chuẩn lưu trữ Kiểm toán Nội bộ &amp; Báo cáo Phòng chống Gian lận
              </p>
            </div>
          </div>

          <div className="no-print flex items-center gap-2">
            <button
              type="button"
              onClick={() => void handleCopy()}
              className="cursor-pointer inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-100 border border-slate-700 transition-colors"
            >
              {copied ? (
                <>
                  <Check className="w-3.5 h-3.5 text-emerald-400" />
                  <span className="text-emerald-300">Đã sao chép!</span>
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5 text-amber-400" />
                  <span>Sao chép Biên bản</span>
                </>
              )}
            </button>

            <button
              type="button"
              onClick={() => window.print()}
              className="cursor-pointer inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold bg-amber-500 hover:bg-amber-400 text-slate-950 transition-colors"
            >
              <Printer className="w-3.5 h-3.5" />
              <span>In / Lưu PDF</span>
            </button>

            <button
              type="button"
              onClick={onClose}
              aria-label="Đóng biên bản"
              className="cursor-pointer p-1.5 rounded-xl hover:bg-slate-800 text-slate-400"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Body */}
        <div className="p-5 overflow-y-auto space-y-4 text-xs">
          {/* Metadata Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 bg-slate-950 p-3.5 rounded-xl border border-slate-800">
            <div>
              <div className="text-slate-400">Mã vụ việc</div>
              <div className="font-mono font-bold text-white text-sm mt-0.5">{dossier.alertId}</div>
            </div>
            <div>
              <div className="text-slate-400">Điểm rủi ro định lượng</div>
              <div className="font-mono font-bold text-amber-400 text-sm mt-0.5">
                {dossier.deterministicRiskScore}/100 ({dossier.confidenceScore}% AI)
              </div>
            </div>
            <div>
              <div className="text-slate-400">Luồng tài khoản</div>
              <div className="font-mono font-semibold text-slate-200 mt-0.5">
                {dossier.primaryAccountId} → {dossier.targetRecipientAccountId}
              </div>
            </div>
            <div>
              <div className="text-slate-400">Trạng thái hồ sơ</div>
              <div className="font-mono font-bold text-emerald-400 mt-0.5">{dossier.status}</div>
            </div>
          </div>

          {/* Executive Summary */}
          <div className="bg-slate-950/90 p-4 rounded-xl border border-slate-800 space-y-1.5">
            <h3 className="text-xs font-bold text-amber-300">
              1. Kết luận Điều tra Nguyên nhân Gốc
            </h3>
            <p className="text-sm text-slate-100 leading-relaxed">{dossier.executiveSummaryVi}</p>
          </div>

          {/* SBV & Personal Data Regulatory Alignment (QĐ 2345, TT 50/2024 amended by TT 77/2025, Law 91/2025 & Decree 356/2025) */}
          <div className="bg-slate-950/90 p-4 rounded-xl border border-violet-500/30 space-y-2.5">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <h3 className="text-xs font-bold text-violet-300">
                2. Đối chiếu Yêu cầu Pháp lý (QĐ 2345 • TT 50/2024 sửa đổi bởi TT 77/2025 • Luật 91/2025 &amp; NĐ 356/2025)
              </h3>
              <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-amber-500/15 text-amber-300 border border-amber-500/30">
                PAD: {dossier.tt77Assessment.article11Clause5cPad.certificationStatus}
              </span>
            </div>
            <ul className="space-y-1.5 text-xs text-slate-200">
              {dossier.regulatoryReferencesVi.map((ref, idx) => (
                <li key={idx} className="flex items-start gap-2">
                  <span className="text-amber-400 font-bold">•</span>
                  <span>{ref}</span>
                </li>
              ))}
            </ul>
            <div className="p-2.5 rounded-lg bg-amber-950/35 border border-amber-500/30 text-[11px] text-amber-200 space-y-1">
              <div className="font-bold">
                Minh bạch Phạm vi Triển khai (Ánh xạ Yêu cầu vs. Chứng nhận / Truyền dữ liệu AI / Kết nối Thực tế):
              </div>
              <p>{dossier.tt77Assessment.article8Clause4.browserLimitationDisclaimerVi}</p>
              <p>{dossier.tt77Assessment.article11Clause5cPad.disclaimerVi}</p>
              <p>{dossier.geminiDataTransmissionDisclosureVi}</p>
              <p>
                Trạng thái tích hợp mạng ngoài: SIMO = <strong>SIMULATED</strong> • VietQR NAPAS = <strong>SIMULATED</strong> • Thanh toán Ngân hàng = <strong>SIMULATED</strong> • Đánh giá pháp lý đầy đủ = <strong>LEGAL_REVIEW_REQUIRED</strong>.
              </p>
            </div>
            <div className="bg-slate-900 p-3 rounded-lg border border-slate-800 font-mono text-[11px] text-emerald-300 overflow-x-auto">
              <div className="text-slate-400 mb-1 font-sans text-xs font-semibold">
                Bản tin Đồng bộ SIMO Mô phỏng (SHA-256 Digest Preview / Server HMAC-SHA-256 Pseudonymization — Luật 91/2025/QH15 &amp; NĐ 356/2025/NĐ-CP; KHÔNG phải ẩn danh hóa tuyệt đối):
              </div>
              <pre>{JSON.stringify(dossier.simoPiiMaskedPayload, null, 2)}</pre>
            </div>
          </div>

          {/* Verified Evidence Table */}
          <div className="bg-slate-950/90 p-4 rounded-xl border border-slate-800 space-y-2">
            <h3 className="text-xs font-bold text-cyan-300">
              3. Danh mục Mã Bằng chứng Đã Kiểm định Tham chiếu ({dossier.verifiedEvidenceList.length} bản ghi)
            </h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {dossier.verifiedEvidenceList.map((item) => (
                <div
                  key={item.id}
                  className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 flex items-center gap-2"
                >
                  <span className="font-mono font-bold text-amber-300 px-2 py-0.5 rounded bg-amber-500/15 border border-amber-500/30 shrink-0">
                    {item.id}
                  </span>
                  <span className="text-slate-200 truncate">{item.description}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Executed Playbook Actions */}
          <div className="bg-slate-950/90 p-4 rounded-xl border border-slate-800 space-y-2">
            <h3 className="text-xs font-bold text-emerald-300">
              4. Biện pháp Xử lý &amp; Kích hoạt Lá chắn Bảo vệ Người dùng
            </h3>
            <div className="space-y-1.5">
              {dossier.executedActionsVi.map((act, i) => (
                <div key={i} className="flex items-center gap-2 text-slate-100">
                  <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
                  <span>{act}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
