'use client';

import { useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity,
  CheckCircle2,
  Cpu,
  FilePlus2,
  FileUp,
  Image as ImageIcon,
  Loader2,
  Network,
  Sparkles,
  User,
  Wand2,
  X,
} from 'lucide-react';
import {
  CASE_BUILDER_PRESETS,
  evaluateLiveCaseInputPreview,
  extractEntitiesFromTextDeterministically,
} from '@/domain/sandbox-synthesizer';
import type { StandardCaseInputSpec } from '@/domain/types';
import { SANDBOX_VISUAL_GALLERY } from '@/infrastructure/sandbox-gallery';
import { prepareClientReceiptImageForUpload } from '@/presentation/utils/client-image-compressor';

interface LiveSandboxModalProps {
  isOpen: boolean;
  isSubmitting: boolean;
  initialSpec?: StandardCaseInputSpec | null;
  asPage?: boolean;
  onClose: () => void;
  onSubmitSandbox: (payload: {
    customTitle?: string;
    rawTranscript: string;
    imageDataUrl?: string;
    recipientAccountNumber?: string;
    recipientOwnerName?: string;
    amountVnd?: number;
    caseInputSpec?: Partial<StandardCaseInputSpec>;
  }) => Promise<boolean>;
}

const CLASSIFICATION_BADGE: Record<
  string,
  { labelVi: string; colorClass: string }
> = {
  CONFIRMED_APP_SCAM: {
    labelVi: 'Dự báo: Lừa đảo thao túng tâm lý (APP Fraud)',
    colorClass: 'bg-red-500/20 text-red-200 border-red-500/40',
  },
  CONFIRMED_ATO_MULE: {
    labelVi: 'Dự báo: Chiếm đoạt tài khoản & rửa tiền (Cyber ATO)',
    colorClass: 'bg-red-500/20 text-red-200 border-red-500/40',
  },
  CONFIRMED_LOGIC_ABUSE: {
    labelVi: 'Dự báo: Khai thác lỗ hổng API (Race Condition / HMAC)',
    colorClass: 'bg-amber-500/20 text-amber-200 border-amber-500/40',
  },
  FALSE_POSITIVE_SAFE: {
    labelVi: 'Dự báo: Giao dịch hợp lệ an toàn (Không khóa oan)',
    colorClass: 'bg-emerald-500/20 text-emerald-200 border-emerald-500/40',
  },
};

export const LiveSandboxModal = ({
  isOpen,
  isSubmitting,
  initialSpec,
  asPage = false,
  onClose,
  onSubmitSandbox,
}: LiveSandboxModalProps) => {
  const defaultPreset = CASE_BUILDER_PRESETS[1]!;
  const [selectedPresetId, setSelectedPresetId] = useState<string>(defaultPreset.id);
  const [spec, setSpec] = useState<StandardCaseInputSpec>(defaultPreset.spec);
  const [debouncedSpec, setDebouncedSpec] = useState<StandardCaseInputSpec>(defaultPreset.spec);
  const [fileError, setFileError] = useState<string | null>(null);
  const isActiveRef = useRef<boolean>(isOpen || asPage);
  const uploadGenerationRef = useRef<number>(0);

  useEffect(() => {
    isActiveRef.current = isOpen || asPage;
    if (!isOpen && !asPage) {
      uploadGenerationRef.current += 1;
      setFileError(null);
    }
    return () => {
      isActiveRef.current = false;
      uploadGenerationRef.current += 1;
    };
  }, [isOpen, asPage]);

  useEffect(() => {
    if (initialSpec) {
      setSpec(initialSpec);
      setDebouncedSpec(initialSpec);
      setSelectedPresetId('EDIT-CURRENT');
    }
  }, [initialSpec]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      setDebouncedSpec(spec);
    }, 120);
    return () => window.clearTimeout(timer);
  }, [spec]);

  const livePreview = useMemo(() => evaluateLiveCaseInputPreview(debouncedSpec), [debouncedSpec]);

  if (!isOpen && !asPage) return null;

  const updateField = <K extends keyof StandardCaseInputSpec>(
    key: K,
    value: StandardCaseInputSpec[K]
  ) => {
    setSpec((prev) => ({ ...prev, [key]: value }));
  };

  const handleSelectPreset = (presetId: string) => {
    const found = CASE_BUILDER_PRESETS.find((p) => p.id === presetId);
    if (!found) return;
    setSelectedPresetId(found.id);
    setSpec({ ...found.spec });
    setFileError(null);
  };

  const handleSelectVisualSample = (sampleId: string) => {
    const sample = SANDBOX_VISUAL_GALLERY.find((s) => s.id === sampleId);
    if (!sample) return;
    setSelectedPresetId(sample.id);
    setSpec((prev) => ({
      ...prev,
      customTitle: sample.title,
      rawTranscript: sample.transcript,
      imageDataUrl: sample.imageDataUrl,
      recipientAccountNumber: sample.recipientAccountNumber,
      recipientOwnerName: sample.recipientOwnerName,
      amountVnd: sample.amountVnd,
      recipientAccountType: 'MULE_SUSPECT',
      recipientAccountAgeDays: 4,
      recipientKycLevel: 'LEVEL_1',
      deviceIntegrity: 'SHARED_EMULATOR_ROOTED',
      inCallCoercionDetected: true,
    }));
    setFileError(null);
  };

  const handleAutoExtractFromTranscript = () => {
    const extracted = extractEntitiesFromTextDeterministically(spec.rawTranscript);
    setSpec((prev) => ({
      ...prev,
      recipientAccountNumber: extracted.recipientAccountNumber,
      recipientOwnerName: extracted.recipientOwnerName,
      amountVnd: extracted.amountVnd,
      customTitle: prev.customTitle || extracted.scamArchetypeVi,
    }));
  };

  const handleFileUpload = async (file: File | undefined) => {
    setFileError(null);
    if (!file) return;
    const uploadGen = ++uploadGenerationRef.current;
    const prepared = await prepareClientReceiptImageForUpload(file);
    if (!isActiveRef.current || uploadGen !== uploadGenerationRef.current) {
      return;
    }
    if (!prepared.ok) {
      setFileError(prepared.errorVi);
      return;
    }
    setSelectedPresetId('CUSTOM-UPLOAD');
    setSpec((prev) => ({
      ...prev,
      imageDataUrl: prepared.dataUrl,
      customTitle: `[Ảnh Bằng chứng] Phân tích hồ sơ ảnh tải lên: ${file.name}`,
      rawTranscript: '',
    }));
  };

  const classBadge =
    CLASSIFICATION_BADGE[livePreview.classification] ??
    CLASSIFICATION_BADGE.CONFIRMED_APP_SCAM!;

  const cardContent = (
    <div
      className={`w-full bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden flex flex-col ${
        asPage ? 'shadow-lg' : 'max-w-5xl shadow-2xl max-h-[94vh] border-slate-700'
      }`}
    >
      {/* Top Modal / Section Header */}
      <div className="px-5 py-3.5 bg-slate-950 border-b border-slate-800 flex items-center justify-between gap-3">
        <div className="flex items-center gap-2.5">
          <div className="h-9 w-9 rounded-xl bg-violet-500/20 border border-violet-500/40 flex items-center justify-center text-violet-300">
            <FilePlus2 className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-white">
              Biểu mẫu Tạo &amp; Kiểm thử Kịch bản Giao dịch Mô phỏng (Chuẩn 4 Phần • 100% Tính toán Động)
            </h2>
            <p className="text-xs text-slate-400">
              Tạo kịch bản tổng hợp hoặc nạp mẫu chuẩn rồi tùy chỉnh thông số để kiểm chứng 5 công cụ định lượng &amp; Trợ lý Gemini (chỉ dùng dữ liệu mô phỏng, không nhập dữ liệu thật)
            </p>
          </div>
        </div>
        {!asPage && (
          <button
            type="button"
            onClick={onClose}
            aria-label="Đóng biểu mẫu"
            className="cursor-pointer p-1.5 rounded-xl hover:bg-slate-800 text-slate-400"
          >
            <X className="w-4 h-4" />
          </button>
        )}
      </div>

        {/* Live Real-Time Deterministic Risk Calculator Preview Bar */}
        <div className="px-5 py-3 bg-slate-950/95 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-2.5">
            <span className="text-xs font-bold text-slate-300">
              Kết quả Định lượng Tức thời (Live Preview):
            </span>
            <span
              className={`text-xs font-bold px-2.5 py-1 rounded-lg border ${
                livePreview.riskScore >= 80
                  ? 'bg-red-500/20 text-red-200 border-red-500/40'
                  : livePreview.riskScore >= 40
                    ? 'bg-amber-500/20 text-amber-200 border-amber-500/40'
                    : 'bg-emerald-500/20 text-emerald-200 border-emerald-500/40'
              }`}
            >
              Điểm rủi ro: {livePreview.riskScore}/100
            </span>
            <span className={`text-xs font-bold px-2.5 py-1 rounded-lg border ${classBadge.colorClass}`}>
              {classBadge.labelVi}
            </span>
          </div>

          <div className="flex flex-wrap items-center gap-2 text-xs">
            <span className="px-2 py-0.5 rounded-md bg-slate-900 border border-slate-800 text-slate-300">
              Z-Score: <strong className="text-amber-300">+{livePreview.zScoreDeviation}σ</strong>
            </span>
            <span className="px-2 py-0.5 rounded-md bg-slate-900 border border-slate-800 text-slate-300">
              Smurfing: <strong className="text-cyan-300">{livePreview.smurfingEntropyIndex}</strong>
            </span>
            <span className="px-2 py-0.5 rounded-md bg-slate-900 border border-slate-800 text-slate-300">
              Cụm Thiết bị: <strong className="text-rose-300">{livePreview.deviceBipartiteClusterScore}</strong>
            </span>
            <span className="px-2 py-0.5 rounded-md bg-slate-900 border border-slate-800 text-slate-300">
              Fan-In: <strong className="text-violet-300">{livePreview.crossVictimFanIn} KH</strong>
            </span>
          </div>
        </div>

        {/* Form Body */}
        <form
          onSubmit={async (e) => {
            e.preventDefault();
            await onSubmitSandbox({
              customTitle: spec.customTitle,
              rawTranscript: spec.rawTranscript,
              imageDataUrl: spec.imageDataUrl,
              recipientAccountNumber: spec.recipientAccountNumber,
              recipientOwnerName: spec.recipientOwnerName,
              amountVnd: spec.amountVnd,
              caseInputSpec: spec,
            });
          }}
          className="p-5 space-y-4 overflow-y-auto flex-1 text-xs"
        >
          {/* Quick Presets & Visual Samples Row */}
          <div className="space-y-2">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="font-bold text-amber-300">
                Nạp nhanh Mẫu Kiểm thử Chuẩn (Sau khi nạp, bạn có thể sửa bất kỳ thông số nào ở 4 phần bên dưới):
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2">
              {CASE_BUILDER_PRESETS.map((preset) => {
                const active = selectedPresetId === preset.id;
                return (
                  <button
                    key={preset.id}
                    type="button"
                    onClick={() => handleSelectPreset(preset.id)}
                    className={`cursor-pointer text-left p-2.5 rounded-xl border transition-all ${
                      active
                        ? 'bg-slate-800 border-amber-400 ring-1 ring-amber-400/40'
                        : 'bg-slate-950 border-slate-800 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-1 font-bold text-white mb-1">
                      <span className="truncate">{preset.badgeVi}</span>
                      {active && <CheckCircle2 className="w-3.5 h-3.5 text-amber-400 shrink-0" />}
                    </div>
                    <p className="text-[11px] text-slate-300 line-clamp-2 leading-snug">
                      {preset.titleVi}
                    </p>
                    <div className="mt-1.5 text-[11px] font-bold text-amber-300">
                      {preset.expectedRiskLabelVi}
                    </div>
                  </button>
                );
              })}
            </div>
          </div>

          {/* 4-Part Standardized Form Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
            {/* PART 1: Sender & Transaction Profile */}
            <div className="lg:col-span-6 bg-slate-950/90 border border-slate-800 rounded-xl p-4 space-y-3">
              <div className="flex items-center gap-2 border-b border-slate-800 pb-2">
                <User className="w-4 h-4 text-cyan-400" />
                <h3 className="text-xs font-bold text-white">
                  Phần 1: Hồ sơ Người gửi &amp; Thông số Giao dịch (Tính Z-Score &amp; Smurfing)
                </h3>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                <div>
                  <label htmlFor="sandbox-sender-name" className="block text-slate-300 font-semibold mb-1">
                    Họ tên chủ ví gửi
                  </label>
                  <input
                    id="sandbox-sender-name"
                    type="text"
                    value={spec.senderName}
                    onChange={(e) => updateField('senderName', e.target.value)}
                    className="w-full bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-white"
                  />
                </div>

                <div>
                  <label htmlFor="sandbox-sender-acc" className="block text-slate-300 font-semibold mb-1">
                    Số điện thoại / Mã ví gửi
                  </label>
                  <input
                    id="sandbox-sender-acc"
                    type="text"
                    value={spec.senderAccountNumber}
                    onChange={(e) => updateField('senderAccountNumber', e.target.value)}
                    className="w-full bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-white"
                  />
                </div>

                <div>
                  <label htmlFor="sandbox-sender-avg" className="block text-slate-300 font-semibold mb-1">
                    Mức giao dịch TB lịch sử (VNĐ)
                  </label>
                  <input
                    id="sandbox-sender-avg"
                    type="number"
                    min={1000}
                    step={1000}
                    value={spec.senderAvgTxVnd}
                    onChange={(e) =>
                      updateField('senderAvgTxVnd', Math.max(1000, Number(e.target.value) || 500000))
                    }
                    className="w-full bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-amber-300 font-bold"
                  />
                </div>

                <div>
                  <label htmlFor="sandbox-amount" className="block text-slate-300 font-semibold mb-1">
                    Tổng số tiền giao dịch này (VNĐ)
                  </label>
                  <input
                    id="sandbox-amount"
                    type="number"
                    min={1000}
                    step={1000}
                    value={spec.amountVnd}
                    onChange={(e) =>
                      updateField('amountVnd', Math.max(1000, Number(e.target.value) || 1000000))
                    }
                    className="w-full bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-emerald-300 font-bold"
                  />
                </div>

                <div>
                  <label htmlFor="sandbox-split-count" className="block text-slate-300 font-semibold mb-1">
                    Số lệnh chia nhỏ liên tiếp (Smurfing)
                  </label>
                  <select
                    id="sandbox-split-count"
                    value={spec.splitTxCount}
                    onChange={(e) => updateField('splitTxCount', Number(e.target.value))}
                    className="w-full bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-white"
                  >
                    <option value={1}>1 lệnh chuyển đơn lẻ</option>
                    <option value={2}>Chia nhỏ 2 lệnh liên tiếp</option>
                    <option value={3}>Chia nhỏ 3 lệnh đều nhau (Smurfing)</option>
                    <option value={4}>Chia nhỏ 4 lệnh đều nhau (Smurfing)</option>
                  </select>
                </div>

                <div>
                  <label htmlFor="sandbox-channel" className="block text-slate-300 font-semibold mb-1">
                    Kênh thực hiện giao dịch
                  </label>
                  <select
                    id="sandbox-channel"
                    value={spec.channel}
                    onChange={(e) =>
                      updateField('channel', e.target.value as StandardCaseInputSpec['channel'])
                    }
                    className="w-full bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-white"
                  >
                    <option value="VIETQR">Quét mã VietQR Liên Ngân hàng</option>
                    <option value="P2P_WALLET">Chuyển tiền Ví sang Ví (P2P)</option>
                    <option value="PAYMENT_GATEWAY">Cổng Thanh toán Thương mại</option>
                    <option value="VOUCHER_REDEEM">API Hoàn tiền / Đổi Voucher</option>
                  </select>
                </div>
              </div>
            </div>

            {/* PART 2: Recipient & Network Profile */}
            <div className="lg:col-span-6 bg-slate-950/90 border border-slate-800 rounded-xl p-4 space-y-3">
              <div className="flex items-center gap-2 border-b border-slate-800 pb-2">
                <Network className="w-4 h-4 text-amber-400" />
                <h3 className="text-xs font-bold text-white">
                  Phần 2: Hồ sơ Tài khoản Người nhận &amp; Mạng lưới (Tính Fan-In &amp; Trust Dampeners)
                </h3>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                <div>
                  <label htmlFor="sandbox-recipient-acc" className="block text-slate-300 font-semibold mb-1">
                    Số tài khoản / Mã ví nhận
                  </label>
                  <input
                    id="sandbox-recipient-acc"
                    type="text"
                    value={spec.recipientAccountNumber}
                    onChange={(e) => updateField('recipientAccountNumber', e.target.value)}
                    className="w-full bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-amber-300 font-bold"
                  />
                </div>

                <div>
                  <label htmlFor="sandbox-recipient-name" className="block text-slate-300 font-semibold mb-1">
                    Tên chủ tài khoản nhận (NAPAS)
                  </label>
                  <input
                    id="sandbox-recipient-name"
                    type="text"
                    value={spec.recipientOwnerName}
                    onChange={(e) => updateField('recipientOwnerName', e.target.value)}
                    className="w-full bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-white font-bold"
                  />
                </div>

                <div className="sm:col-span-2">
                  <label htmlFor="sandbox-recipient-type" className="block text-slate-300 font-semibold mb-1">
                    Phân loại uy tín đơn vị thụ hưởng
                  </label>
                  <select
                    id="sandbox-recipient-type"
                    value={spec.recipientAccountType}
                    onChange={(e) =>
                      updateField(
                        'recipientAccountType',
                        e.target.value as StandardCaseInputSpec['recipientAccountType']
                      )
                    }
                    className="w-full bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-white font-semibold"
                  >
                    <option value="MULE_SUSPECT">
                      Tài khoản cá nhân mới mở / Nghi vấn nằm trong danh sách theo dõi (Mule Suspect)
                    </option>
                    <option value="CONSUMER">
                      Tài khoản cá nhân thông thường
                    </option>
                    <option value="TRUSTED_INSTITUTION">
                      Đơn vị Y tế / Bệnh viện / Trường học / Đối tác Uy tín đã xác thực (Giảm trừ -22đ)
                    </option>
                  </select>
                </div>

                <div>
                  <label htmlFor="sandbox-recipient-age" className="block text-slate-300 font-semibold mb-1">
                    Tuổi tài khoản nhận (Số ngày mở)
                  </label>
                  <input
                    id="sandbox-recipient-age"
                    type="number"
                    min={1}
                    value={spec.recipientAccountAgeDays}
                    onChange={(e) =>
                      updateField('recipientAccountAgeDays', Math.max(1, Number(e.target.value) || 3))
                    }
                    className="w-full bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-white"
                  />
                </div>

                <div>
                  <label htmlFor="sandbox-fanin" className="block text-slate-300 font-semibold mb-1">
                    Số nạn nhân khác cùng chuyển vào TK này (Fan-In)
                  </label>
                  <select
                    id="sandbox-fanin"
                    value={spec.crossVictimFanInCount}
                    onChange={(e) => updateField('crossVictimFanInCount', Number(e.target.value))}
                    className="w-full bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-white"
                  >
                    <option value={0}>0 người khác (Giao dịch 1-1 độc lập)</option>
                    <option value={1}>+1 nạn nhân khác cùng chuyển vào (Tổng 2 KH)</option>
                    <option value={2}>+2 nạn nhân khác cùng chuyển vào (Tổng 3 KH)</option>
                    <option value={3}>+3 nạn nhân khác cùng chuyển vào (Tổng 4 KH)</option>
                  </select>
                </div>
              </div>
            </div>

            {/* PART 3: Cyber, Device, QĐ 2345 In-Call & API Telemetry */}
            <div className="lg:col-span-6 bg-slate-950/90 border border-slate-800 rounded-xl p-4 space-y-3">
              <div className="flex items-center gap-2 border-b border-slate-800 pb-2">
                <Cpu className="w-4 h-4 text-violet-400" />
                <h3 className="text-xs font-bold text-white">
                  Phần 3: Tín hiệu Thiết bị, Phiên Đăng nhập, Hành vi QĐ 2345 &amp; API
                </h3>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                <div>
                  <label htmlFor="sandbox-device-integrity" className="block text-slate-300 font-semibold mb-1">
                    Độ toàn vẹn Thiết bị (Thông tư 50)
                  </label>
                  <select
                    id="sandbox-device-integrity"
                    value={spec.deviceIntegrity}
                    onChange={(e) =>
                      updateField(
                        'deviceIntegrity',
                        e.target.value as StandardCaseInputSpec['deviceIntegrity']
                      )
                    }
                    className="w-full bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-white"
                  >
                    <option value="TRUSTED_PERSONAL_DEVICE">
                      Thiết bị chính chủ an toàn (Secure Enclave)
                    </option>
                    <option value="SHARED_EMULATOR_ROOTED">
                      Máy giả lập Android đã Root dùng chung cụm Mule (DEV-EMU-666)
                    </option>
                    <option value="UNRECOGNIZED_FOREIGN_IP">
                      Thiết bị lạ qua VPN / Proxy quốc tế ẩn danh
                    </option>
                  </select>
                </div>

                <div>
                  <label htmlFor="sandbox-session-security" className="block text-slate-300 font-semibold mb-1">
                    Bảo mật Phiên &amp; Xác thực Sinh trắc học
                  </label>
                  <select
                    id="sandbox-session-security"
                    value={spec.sessionSecurity}
                    onChange={(e) =>
                      updateField(
                        'sessionSecurity',
                        e.target.value as StandardCaseInputSpec['sessionSecurity']
                      )
                    }
                    className="w-full bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-white"
                  >
                    <option value="BIOMETRIC_FACEID_PASSED">
                      Đã xác thực FaceID + NFC CCCD chính chủ (QĐ 2345)
                    </option>
                    <option value="SESSION_SURVIVED_PASSWORD_RESET">
                      CẢNH BÁO ATO: Phiên cũ sống sót sau khi đổi mật khẩu (Token Replay)
                    </option>
                    <option value="NORMAL_LOGIN">
                      Đăng nhập mật khẩu / OTP tiêu chuẩn
                    </option>
                  </select>
                </div>

                <div className="sm:col-span-2 bg-slate-900 p-2.5 rounded-lg border border-slate-800 flex items-center justify-between gap-3">
                  <label htmlFor="sandbox-incall-coercion" className="cursor-pointer flex-1">
                    <div className="font-bold text-amber-300">
                      Tín hiệu Thao túng trong Cuộc gọi khi quét FaceID (In-Call Coercion)
                    </div>
                    <div className="text-[11px] text-slate-400">
                      Khách đang nghe cuộc gọi lạ kéo dài &gt;15 phút + Copy/Paste STK từ Clipboard lúc quét mặt
                    </div>
                  </label>
                  <input
                    id="sandbox-incall-coercion"
                    type="checkbox"
                    checked={spec.inCallCoercionDetected}
                    onChange={(e) => updateField('inCallCoercionDetected', e.target.checked)}
                    className="h-4 w-4 accent-amber-500 cursor-pointer shrink-0"
                  />
                </div>

                <div className="sm:col-span-2 bg-slate-900 p-2.5 rounded-lg border border-red-500/30 flex items-center justify-between gap-3">
                  <label htmlFor="sandbox-deepfake-cam" className="cursor-pointer flex-1">
                    <div className="font-bold text-rose-300">
                      Chống Deepfake / Camera Ảo (ISO/IEC 30107-3 Liveness PAD)
                    </div>
                    <div className="text-[11px] text-slate-400">
                      Bật cờ nếu phát hiện hook Camera ảo chèn video Deepfake qua mặt xác thực sinh trắc học
                    </div>
                  </label>
                  <input
                    id="sandbox-deepfake-cam"
                    type="checkbox"
                    checked={Boolean(spec.deepfakeOrVirtualCamDetected)}
                    onChange={(e) => updateField('deepfakeOrVirtualCamDetected', e.target.checked)}
                    className="h-4 w-4 accent-rose-500 cursor-pointer shrink-0"
                  />
                </div>

                <div>
                  <label htmlFor="sandbox-api-burst" className="block text-slate-300 font-semibold mb-1">
                    Mật độ Request API đồng thời / 100ms
                  </label>
                  <select
                    id="sandbox-api-burst"
                    value={spec.apiConcurrentRequests100ms}
                    onChange={(e) => updateField('apiConcurrentRequests100ms', Number(e.target.value))}
                    className="w-full bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-white"
                  >
                    <option value={1}>1 request / 100ms (Bình thường)</option>
                    <option value={2}>2 requests / 100ms (Bình thường)</option>
                    <option value={12}>12 requests / 100ms (Tấn công Race Condition TOCTOU)</option>
                    <option value={25}>25 requests / 100ms (Burst Script Mức Nghiêm Trọng)</option>
                  </select>
                </div>

                <div>
                  <label htmlFor="sandbox-hmac" className="block text-slate-300 font-semibold mb-1">
                    Chữ ký Bảo mật Callback Webhook HMAC
                  </label>
                  <select
                    id="sandbox-hmac"
                    value={spec.webhookHmacValid ? 'VALID' : 'INVALID'}
                    onChange={(e) => updateField('webhookHmacValid', e.target.value === 'VALID')}
                    className="w-full bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-white"
                  >
                    <option value="VALID">Chữ ký HMAC-SHA256 Hợp lệ</option>
                    <option value="INVALID">SAI CHỮ KÝ (Giả mạo Callback Webhook)</option>
                  </select>
                </div>
              </div>
            </div>

            {/* PART 4: Multimodal Evidence (Transcript & Image OCR) */}
            <div className="lg:col-span-6 bg-slate-950/90 border border-slate-800 rounded-xl p-4 space-y-3">
              <div className="flex items-center justify-between gap-2 border-b border-slate-800 pb-2">
                <div className="flex items-center gap-2">
                  <ImageIcon className="w-4 h-4 text-emerald-400" />
                  <h3 className="text-xs font-bold text-white">
                    Phần 4: Bằng chứng Tin nhắn / Hóa đơn &amp; Ảnh chụp Màn hình (Vision OCR)
                  </h3>
                </div>
                <button
                  type="button"
                  onClick={handleAutoExtractFromTranscript}
                  className="cursor-pointer inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-amber-300 border border-slate-700 font-bold"
                >
                  <Wand2 className="w-3.5 h-3.5" />
                  <span>Tự bóc tách STK &amp; Số tiền từ chữ</span>
                </button>
              </div>

              <div>
                <label htmlFor="sandbox-title" className="block text-slate-300 font-semibold mb-1">
                  Tiêu đề Hồ sơ Vụ việc
                </label>
                <input
                  id="sandbox-title"
                  type="text"
                  value={spec.customTitle ?? ''}
                  onChange={(e) => updateField('customTitle', e.target.value)}
                  placeholder="Nhập tiêu đề hồ sơ..."
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-white"
                />
              </div>

              <div
                data-testid="sandbox-synthetic-warning"
                className="p-2.5 rounded-lg bg-amber-950/45 border border-amber-500/35 text-[11px] text-amber-200 leading-relaxed"
              >
                <strong className="text-amber-300">Lưu ý dữ liệu mô phỏng:</strong> Chỉ nhập kịch bản giả lập hoặc tải ảnh mẫu mô phỏng.{' '}
                <strong>KHÔNG</strong> tải CCCD, số tài khoản, đoạn chat hoặc ảnh chụp giao dịch thật. Hệ thống không thể tự phân biệt kỹ thuật giữa ảnh thật và ảnh mô phỏng.
              </div>

              <div>
                <label htmlFor="sandbox-transcript" className="block text-slate-300 font-semibold mb-1">
                  Nội dung tin nhắn / kịch bản / hóa đơn mô phỏng (Hoặc để trống khi tải ảnh mẫu để Gemini Vision đọc OCR)
                </label>
                <textarea
                  id="sandbox-transcript"
                  rows={2}
                  value={spec.rawTranscript}
                  onChange={(e) => updateField('rawTranscript', e.target.value)}
                  placeholder="Dán đoạn chat giả lập hoặc mô tả kịch bản giao dịch mô phỏng..."
                  className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 text-slate-100 leading-relaxed"
                />
              </div>

              {/* 3 Sample Images + Custom Upload */}
              <div className="flex flex-wrap items-center justify-between gap-2 pt-1">
                <div className="flex flex-wrap items-center gap-1.5">
                  <span className="text-slate-400 font-semibold">Đính kèm nhanh 3 ảnh mẫu:</span>
                  {SANDBOX_VISUAL_GALLERY.map((sample) => (
                    <button
                      key={sample.id}
                      type="button"
                      onClick={() => handleSelectVisualSample(sample.id)}
                      className="cursor-pointer px-2 py-1 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-200 font-semibold"
                    >
                      {sample.badgeVi}
                    </button>
                  ))}
                </div>

                <label
                  htmlFor="sandbox-image-upload"
                  className="cursor-pointer inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-violet-600/25 hover:bg-violet-600/40 text-violet-200 border border-violet-500/40 font-bold"
                >
                  <FileUp className="w-3.5 h-3.5" />
                  <span>Tải ảnh mẫu mô phỏng...</span>
                </label>
                <input
                  id="sandbox-image-upload"
                  type="file"
                  accept="image/png,image/jpeg,image/webp"
                  onChange={(e) => handleFileUpload(e.target.files?.[0])}
                  className="hidden"
                />
              </div>
              {fileError && <p className="text-red-400">{fileError}</p>}

              {spec.imageDataUrl && (
                <div className="flex items-center justify-between gap-3 bg-slate-900 p-2 rounded-lg border border-slate-800">
                  <div className="flex items-center gap-2.5">
                    {/* eslint-disable-next-line @next/next/no-img-element */}
                    <img
                      src={spec.imageDataUrl}
                      alt="Preview"
                      className="h-12 w-20 object-cover rounded border border-slate-700 bg-slate-950"
                    />
                    <span className="text-slate-300">
                      Đã đính kèm ảnh bằng chứng đa phương thức cho Gemini Vision
                    </span>
                  </div>
                  <button
                    type="button"
                    onClick={() => updateField('imageDataUrl', undefined)}
                    className="cursor-pointer text-slate-400 hover:text-red-300 px-2 py-1"
                  >
                    Gỡ ảnh
                  </button>
                </div>
              )}
            </div>
          </div>

          {/* Active Risk Factors Breakdown in Form Footer */}
          <div className="bg-slate-950 border border-slate-800 rounded-xl p-3 flex flex-wrap items-center justify-between gap-3">
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="font-bold text-slate-300 flex items-center gap-1">
                <Activity className="w-3.5 h-3.5 text-amber-400" />
                <span>Các trọng số đang kích hoạt theo thông số bạn nhập:</span>
              </span>
              {livePreview.factors.map((f) => (
                <span
                  key={f.id}
                  className={`px-2 py-0.5 rounded-md font-bold ${
                    f.kind === 'TRUST_DAMPENER'
                      ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                      : 'bg-red-500/20 text-red-300 border border-red-500/30'
                  }`}
                >
                  {f.deltaScore > 0 ? `+${f.deltaScore}đ` : `${f.deltaScore}đ`} • {f.labelVi}
                </span>
              ))}
            </div>

            <div className="flex items-center gap-2 ml-auto">
              {!asPage && (
                <button
                  type="button"
                  onClick={onClose}
                  className="cursor-pointer px-4 py-2 rounded-xl text-xs font-bold text-slate-300 hover:bg-slate-800"
                >
                  Đóng
                </button>
              )}
              <button
                type="submit"
                disabled={isSubmitting}
                className="cursor-pointer inline-flex items-center gap-2 px-5 py-2.5 rounded-xl text-xs font-bold bg-amber-500 hover:bg-amber-400 text-slate-950 shadow-lg"
              >
                {isSubmitting ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    <span>Đang dựng Đồ thị &amp; Chạy Gemini...</span>
                  </>
                ) : (
                  <>
                    <Sparkles className="w-4 h-4" />
                    <span>Tạo Hồ sơ, Dựng Đồ thị &amp; Chạy Điều tra Ngay</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </form>
      </div>
  );

  if (asPage) {
    return cardContent;
  }

  return (
    <div className="fixed inset-0 z-50 bg-slate-950/90 backdrop-blur-sm flex items-center justify-center p-3 sm:p-4">
      {cardContent}
    </div>
  );
};
