'use client';

import { useEffect, useState } from 'react';
import {
  AlertOctagon,
  AlertTriangle,
  ArrowRight,
  BatteryCharging,
  Camera,
  CheckCircle2,
  FileUp,
  HeartHandshake,
  Loader2,
  PhoneCall,
  QrCode,
  ReceiptText,
  RefreshCw,
  SendToBack,
  ShieldAlert,
  ShieldCheck,
  Signal,
  Sparkles,
  Store,
  Volume2,
  Wallet,
  Wifi,
  X,
} from 'lucide-react';
import {
  MERCHANT_RECEIPT_PRESETS,
  type MerchantBillVerificationResult,
} from '@/domain/merchant-verifier';
import type {
  Account,
  ConsumerTransferDecision,
  MerchantVisionVerificationBundle,
  ShieldRule,
  Transaction,
} from '@/domain/types';
import { evaluateRecipientTrustTrafficLight } from '@/domain/shield-evaluator';
import {
  inspectVietQrSample,
  parseRawEmvVietQrPayload,
  type VietQrInspectionResult,
} from '@/domain/vietqr-inspector';
import { prepareClientReceiptImageForUpload } from '@/presentation/utils/client-image-compressor';

interface ConsumerWalletSimulatorProps {
  isOpen: boolean;
  isSplitDocked?: boolean;
  prefillAccount: string;
  prefillAmount: number;
  activeShieldRules: ShieldRule[];
  accounts?: Account[];
  transactions?: Transaction[];
  lastDecision: ConsumerTransferDecision | null;
  onClose: () => void;
  onSimulateTransfer: (params: {
    senderAccountId?: string;
    recipientAccount: string;
    amountVnd: number;
    message: string;
    idempotencyKey?: string;
  }) => Promise<ConsumerTransferDecision | null>;
  onAcknowledgeDeEscalation?: (params: {
    recipientAccount: string;
    amountVnd: number;
  }) => Promise<boolean>;
  onEscalateToOps?: (params: {
    recipientAccount: string;
    amountVnd: number;
    message: string;
  }) => Promise<boolean>;
  onVerifyMerchantReceipt?: (params: {
    claimedTxId: string;
    claimedAmountVnd: number;
    merchantAccountIdOrNumber?: string;
  }) => Promise<{ verification?: MerchantBillVerificationResult; errorVi?: string }>;
  onVerifyMerchantVision?: (params: {
    imageDataUrl: string;
    merchantAccountIdOrNumber?: string;
  }) => Promise<{ verification?: MerchantVisionVerificationBundle; errorVi?: string }>;
}

export const ConsumerWalletSimulator = ({
  isOpen,
  isSplitDocked = false,
  prefillAccount,
  prefillAmount,
  activeShieldRules,
  accounts = [],
  transactions: _transactions = [],
  lastDecision,
  onClose,
  onSimulateTransfer,
  onAcknowledgeDeEscalation,
  onEscalateToOps,
  onVerifyMerchantReceipt,
  onVerifyMerchantVision,
}: ConsumerWalletSimulatorProps) => {
  void _transactions;
  const [walletMode, setWalletMode] = useState<'CONSUMER' | 'MERCHANT'>('CONSUMER');
  const [recipientAccount, setRecipientAccount] = useState(prefillAccount);
  const [amountVnd, setAmountVnd] = useState(prefillAmount);
  const [message, setMessage] = useState(
    'Chuyen tien xac minh tai san theo yeu cau cong an'
  );
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isEscalating, setIsEscalating] = useState(false);
  const [escalatedSuccess, setEscalatedSuccess] = useState(false);
  const [selfRescuedDone, setSelfRescuedDone] = useState(false);
  const [isAcknowledging, setIsAcknowledging] = useState(false);
  const [qrScanResult, setQrScanResult] = useState<VietQrInspectionResult | null>(null);
  const [showRawQrTester, setShowRawQrTester] = useState(false);
  const [rawQrPayloadInput, setRawQrPayloadInput] = useState(
    '00020101021238570010A00000072701270006970407011319039998887770208QRIBFTTA53037045408180000005802VN62300826XAC MINH TAI SAN HOAN TIEN6304A9F2'
  );
  const [rawQrBrandInput, setRawQrBrandInput] = useState(
    'CỔNG HOÀN TIỀN GIAO HÀNG NHANH (GHN EXPRESS)'
  );
  const [merchClaimedTxId, setMerchClaimedTxId] = useState('TXN-MERCH-OK');
  const [merchClaimedAmount, setMerchClaimedAmount] = useState(4_850_000);
  const [merchTargetAccount, setMerchTargetAccount] = useState('ACC-HOSP-800');
  const [merchantResult, setMerchantResult] = useState<MerchantBillVerificationResult | null>(null);
  const [isVerifyingMerchant, setIsVerifyingMerchant] = useState(false);
  const [merchantErrorVi, setMerchantErrorVi] = useState<string | null>(null);
  const [visionPreviewUrl, setVisionPreviewUrl] = useState<string | null>(null);
  const [isScanningVision, setIsScanningVision] = useState(false);
  const [visionErrorVi, setVisionErrorVi] = useState<string | null>(null);
  const [visionResult, setVisionResult] = useState<MerchantVisionVerificationBundle | null>(null);
  const [selectedSenderId] = useState('ACC-USR-103');
  const [attemptKey, setAttemptKey] = useState<string>(() => `IDEM-${Date.now().toString(36)}`);

  const refreshAttemptKey = () => {
    setAttemptKey(`IDEM-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`);
  };

  const runMerchantVisionScan = async (imageDataUrl: string) => {
    if (!onVerifyMerchantVision || isScanningVision) return;
    setVisionErrorVi(null);
    setIsScanningVision(true);
    try {
      const res = await onVerifyMerchantVision({
        imageDataUrl,
        merchantAccountIdOrNumber: merchTargetAccount,
      });
      if (res.verification) {
        setVisionResult(res.verification);
        if (res.verification.extractedFields?.claimedTransactionId) {
          setMerchClaimedTxId(res.verification.extractedFields.claimedTransactionId);
        }
        if (res.verification.extractedFields?.claimedAmountVnd) {
          setMerchClaimedAmount(res.verification.extractedFields.claimedAmountVnd);
        }
      }
      if (res.errorVi && !res.verification) {
        setVisionErrorVi(res.errorVi);
      }
    } finally {
      setIsScanningVision(false);
    }
  };

  const handleMerchantReceiptFile = async (file: File | undefined) => {
    setVisionErrorVi(null);
    if (!file) return;
    const prepared = await prepareClientReceiptImageForUpload(file);
    if (!prepared.ok) {
      setVisionErrorVi(prepared.errorVi);
      return;
    }
    setVisionPreviewUrl(prepared.dataUrl);
    setVisionResult(null);
    void runMerchantVisionScan(prepared.dataUrl);
  };

  const speakSoundbox = (text: string) => {
    try {
      if (typeof window !== 'undefined' && 'speechSynthesis' in window) {
        window.speechSynthesis.cancel();
        const utter = new SpeechSynthesisUtterance(text);
        utter.lang = 'vi-VN';
        utter.rate = 1.05;
        window.speechSynthesis.speak(utter);
      }
    } catch {
      // Safe fallback on headless browsers
    }
  };

  const handleVerifyMerchantReceipt = async (
    txId: string,
    claimedAmt: number,
    merchantTarget: string = merchTargetAccount
  ) => {
    setMerchClaimedTxId(txId);
    setMerchClaimedAmount(claimedAmt);
    setMerchTargetAccount(merchantTarget);
    setMerchantErrorVi(null);
    setIsVerifyingMerchant(true);
    try {
      let res: { verification?: MerchantBillVerificationResult; errorVi?: string };
      if (onVerifyMerchantReceipt) {
        res = await onVerifyMerchantReceipt({
          claimedTxId: txId,
          claimedAmountVnd: claimedAmt,
          merchantAccountIdOrNumber: merchantTarget,
        });
      } else {
        const apiRes = await fetch('/api/merchant/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            claimedTxId: txId,
            claimedAmountVnd: Math.max(0, Math.round(claimedAmt || 0)),
            merchantAccountIdOrNumber: merchantTarget,
          }),
        });
        const data = (await apiRes.json().catch(() => ({}))) as {
          verification?: MerchantBillVerificationResult;
          errorVi?: string;
        };
        res = apiRes.ok
          ? { verification: data.verification }
          : { errorVi: data.errorVi || 'Lỗi đối soát Tiểu thương trên máy chủ.' };
      }

      if (res.verification) {
        setMerchantResult(res.verification);
      } else {
        setMerchantErrorVi(res.errorVi || 'Không nhận được kết quả đối soát từ máy chủ.');
      }
    } catch {
      setMerchantErrorVi('Mất kết nối tới máy chủ đối soát Tiểu thương (/api/merchant/verify).');
    } finally {
      setIsVerifyingMerchant(false);
    }
  };

  const senderAccount =
    accounts.find((a) => a.id === selectedSenderId) ??
    accounts.find((a) => a.id === 'ACC-USR-103') ??
    accounts.find((a) => a.accountType === 'CONSUMER');
  const walletBalanceVnd = senderAccount?.balanceVnd ?? 45_000_000;
  const senderDisplayName = senderAccount?.ownerName.split('(')[0]?.trim() || 'Nguyễn Thị Thu Hà';

  const handleScanVietQr = async (sampleId: string) => {
    const inspected = inspectVietQrSample(sampleId);
    setQrScanResult(inspected);
    setRecipientAccount(inspected.recipientAccountNumber);
    setAmountVnd(inspected.amountVnd);
    setMessage(inspected.transferMessage);
    setSelfRescuedDone(false);
    setIsSubmitting(true);
    try {
      await onSimulateTransfer({
        senderAccountId: senderAccount?.id,
        recipientAccount: inspected.recipientAccountNumber,
        amountVnd: inspected.amountVnd,
        message: inspected.transferMessage,
        idempotencyKey: attemptKey,
      });
      refreshAttemptKey();
    } finally {
      setIsSubmitting(false);
    }
  };

  useEffect(() => {
    setRecipientAccount(prefillAccount);
    setSelfRescuedDone(false);
    refreshAttemptKey();
  }, [prefillAccount]);

  useEffect(() => {
    setAmountVnd(prefillAmount);
    refreshAttemptKey();
  }, [prefillAmount]);

  if (!isOpen && !isSplitDocked) return null;

  const isTargetProtected = activeShieldRules.some(
    (r) =>
      r.active &&
      (r.targetAccountNumber.toUpperCase() === recipientAccount.trim().toUpperCase() ||
        r.targetAccountId.toUpperCase() === recipientAccount.trim().toUpperCase())
  );

  const trustLight = evaluateRecipientTrustTrafficLight(
    recipientAccount,
    activeShieldRules,
    accounts
  );

  const walletCard = (
    <aside
      className={`w-full bg-slate-950 border-[3px] border-slate-700/90 rounded-[32px] shadow-2xl overflow-hidden flex flex-col ${isSplitDocked ? 'h-full' : 'max-w-md max-h-[92vh]'
        }`}
    >
      {/* Realistic Smartphone Top Bar (Dynamic Island & Status Indicators) */}
      <div className="bg-slate-950 px-5 pt-2.5 pb-1.5 flex items-center justify-between text-[11px] font-bold text-slate-300 shrink-0">
        <span>09:41</span>
        <div className="w-24 h-4 rounded-full bg-black border border-slate-800 flex items-center justify-center gap-1.5">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
          <span className="text-[9px] text-slate-400">Aegis Shield</span>
        </div>
        <div className="flex items-center gap-1.5">
          <Signal className="w-3 h-3" />
          <Wifi className="w-3 h-3" />
          <BatteryCharging className="w-3.5 h-3.5 text-emerald-400" />
        </div>
      </div>

      {/* MoMo Wallet App Header + Balance Pill */}
      <div className="px-4 py-2.5 bg-gradient-to-r from-[#A50064]/35 via-slate-900 to-slate-900 border-y border-slate-800 flex items-center justify-between gap-2 shrink-0">
        <div className="flex items-center gap-2 min-w-0">
          <div className="h-8 w-8 rounded-xl bg-[#A50064] flex items-center justify-center text-white shadow-sm shrink-0">
            <Wallet className="w-4 h-4" />
          </div>
          <div className="min-w-0">
            <h2 className="text-xs font-bold text-white truncate">
              Ví Điện tử MoMo • {senderDisplayName}
            </h2>
            <div className="text-[11px] text-emerald-300 font-bold" data-testid="wallet-live-balance">
              Số dư khả dụng: {walletBalanceVnd.toLocaleString('vi-VN')} ₫
            </div>
          </div>
        </div>
        <button
          type="button"
          onClick={onClose}
          aria-label="Đóng Ví mô phỏng"
          className="cursor-pointer p-1.5 rounded-xl bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700 shrink-0"
        >
          <X className="w-3.5 h-3.5" />
        </button>
      </div>

      {/* Scrollable Phone Screen Body */}
      <div className="overflow-y-auto p-3.5 space-y-3 flex-1 bg-[#090E1A]">
        {/* Dual Persona Switcher: Consumer P2P vs. Merchant Soundbox */}
        <div className="grid grid-cols-2 gap-1.5 bg-slate-900 p-1 rounded-xl border border-slate-800 text-[11px] font-bold">
          <button
            type="button"
            onClick={() => setWalletMode('CONSUMER')}
            className={`cursor-pointer py-1.5 px-2 rounded-lg flex items-center justify-center gap-1.5 transition-colors ${walletMode === 'CONSUMER'
              ? 'bg-amber-500 text-slate-950 shadow-sm'
              : 'text-slate-300 hover:text-white'
              }`}
          >
            <Wallet className="w-3.5 h-3.5" />
            <span>Khách hàng (P2P)</span>
          </button>
          <button
            type="button"
            onClick={() => setWalletMode('MERCHANT')}
            className={`cursor-pointer py-1.5 px-2 rounded-lg flex items-center justify-center gap-1.5 transition-colors ${walletMode === 'MERCHANT'
              ? 'bg-[#A50064] text-white shadow-sm'
              : 'text-slate-300 hover:text-white'
              }`}
          >
            <Store className="w-3.5 h-3.5" />
            <span>Tiểu thương (Bill &amp; Loa)</span>
          </button>
        </div>

        {walletMode === 'MERCHANT' ? (
          <div className="space-y-3">
            {/* Soundbox Speaker Status */}
            <div className="p-3 rounded-xl bg-gradient-to-r from-[#A50064]/25 to-slate-900 border border-pink-500/40 text-xs space-y-1">
              <div className="flex items-center justify-between gap-2 font-bold text-pink-200">
                <span className="flex items-center gap-1.5">
                  <Volume2 className="w-4 h-4 text-pink-400" />
                  <span>Loa MoMo Soundbox &amp; Vision OCR</span>
                </span>
                <span className="text-[10px] px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                  Core Ledger (Demo)
                </span>
              </div>
              <p className="text-[11px] text-slate-300 leading-relaxed">
                Quét ảnh Bill bằng <strong>Gemini Vision</strong> và đối chiếu Sổ cái Hợp nhất — Tự tách rõ thông tin OCR với dữ liệu Core Ledger.
              </p>
            </div>

            {/* Merchant Vision Intelligence Upload & OCR Verification Card */}
            {onVerifyMerchantVision && (
              <div className="bg-slate-900/95 border border-cyan-500/35 rounded-2xl p-3 space-y-2.5 text-xs">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-bold text-cyan-300 flex items-center gap-1.5">
                    <Sparkles className="w-3.5 h-3.5" />
                    <span>AI Vision Quét Ảnh Bill (Không lưu ảnh gốc)</span>
                  </span>
                  {visionPreviewUrl && (
                    <button
                      type="button"
                      onClick={() => {
                        setVisionPreviewUrl(null);
                        setVisionResult(null);
                        setVisionErrorVi(null);
                      }}
                      className="cursor-pointer text-[10px] text-slate-400 hover:text-white underline"
                    >
                      Xóa ảnh
                    </button>
                  )}
                </div>

                <div className="grid grid-cols-2 gap-1.5">
                  <label
                    htmlFor="merch-vision-upload"
                    className="cursor-pointer py-2 px-2.5 rounded-xl bg-slate-950 hover:bg-slate-800 border border-slate-700 text-slate-100 font-bold text-[11px] flex items-center justify-center gap-1.5 transition-colors"
                  >
                    <FileUp className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                    <span>Tải ảnh Bill</span>
                  </label>
                  <input
                    id="merch-vision-upload"
                    type="file"
                    accept="image/png,image/jpeg,image/webp"
                    onChange={(e) => {
                      handleMerchantReceiptFile(e.target.files?.[0]);
                      e.target.value = '';
                    }}
                    className="hidden"
                  />

                  <label
                    htmlFor="merch-vision-camera"
                    className="cursor-pointer py-2 px-2.5 rounded-xl bg-slate-950 hover:bg-slate-800 border border-slate-700 text-slate-100 font-bold text-[11px] flex items-center justify-center gap-1.5 transition-colors"
                  >
                    <Camera className="w-3.5 h-3.5 text-pink-400 shrink-0" />
                    <span>Chụp Camera</span>
                  </label>
                  <input
                    id="merch-vision-camera"
                    type="file"
                    accept="image/png,image/jpeg,image/webp"
                    capture="environment"
                    onChange={(e) => {
                      handleMerchantReceiptFile(e.target.files?.[0]);
                      e.target.value = '';
                    }}
                    className="hidden"
                  />
                </div>

                {visionPreviewUrl && (
                  <div className="flex items-center justify-between gap-2.5 bg-slate-950 p-2 rounded-xl border border-slate-800">
                    <div className="flex items-center gap-2 min-w-0">
                      {/* eslint-disable-next-line @next/next/no-img-element */}
                      <img
                        src={visionPreviewUrl}
                        alt="Xem trước Bill chuyển khoản"
                        className="h-11 w-14 object-cover rounded-lg border border-slate-700 bg-black shrink-0"
                      />
                      <span className="text-[11px] text-slate-300 truncate">
                        {isScanningVision
                          ? 'Gemini Vision đang trích xuất & đối chiếu...'
                          : 'Đã tải ảnh tạm thời trong phiên'}
                      </span>
                    </div>
                    <button
                      type="button"
                      disabled={isScanningVision}
                      onClick={() => void runMerchantVisionScan(visionPreviewUrl)}
                      className="cursor-pointer disabled:opacity-50 px-2 py-1 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-200 border border-cyan-500/40 font-bold text-[10px] flex items-center gap-1 shrink-0"
                    >
                      {isScanningVision ? (
                        <Loader2 className="w-3 h-3 animate-spin" />
                      ) : (
                        <RefreshCw className="w-3 h-3" />
                      )}
                      <span>Thử lại OCR</span>
                    </button>
                  </div>
                )}

                {visionErrorVi && (
                  <div className="p-2.5 rounded-xl bg-red-950/70 border border-red-500/60 text-red-100 text-[11px] font-semibold">
                    {visionErrorVi}
                  </div>
                )}

                {visionResult && (
                  <div className="space-y-2">
                    {/* Card 1: AI-Extracted Claims (Clearly Separated as Unverified OCR) */}
                    {visionResult.extractedFields && (
                      <div className="p-2.5 rounded-xl bg-slate-950 border border-slate-700 space-y-1 text-[11px]">
                        <div className="flex items-center justify-between gap-2 font-bold text-cyan-300">
                          <span>1. Thông tin AI OCR Trích xuất (Khai báo trên ảnh)</span>
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-200">
                            {visionResult.extractedFields.imageQualityStatus} • ~
                            {Math.round(visionResult.extractedFields.fieldConfidence.overall * 100)}%
                          </span>
                        </div>
                        <div className="grid grid-cols-2 gap-1 text-slate-200">
                          <div>
                            Mã GD: <strong>{visionResult.extractedFields.claimedTransactionId ?? 'Thiếu'}</strong>
                          </div>
                          <div>
                            Số tiền:{' '}
                            <strong>
                              {visionResult.extractedFields.claimedAmountVnd !== null
                                ? `${visionResult.extractedFields.claimedAmountVnd.toLocaleString('vi-VN')} ${visionResult.extractedFields.currency}`
                                : 'Không rõ'}
                            </strong>
                          </div>
                          <div className="col-span-2 truncate">
                            Người nhận ghi trên ảnh:{' '}
                            <strong>{visionResult.extractedFields.claimedRecipientAccount ?? 'Thiếu'}</strong>
                          </div>
                        </div>
                        {visionResult.extractedFields.missingFields.length > 0 && (
                          <div className="text-amber-300 font-semibold">
                            Trường thiếu: {visionResult.extractedFields.missingFields.join(', ')}
                          </div>
                        )}
                        <div className="text-[10px] text-slate-400 italic">
                          {visionResult.confidenceNoteVi}
                        </div>
                      </div>
                    )}

                    {/* Card 2: Authoritative Unified Ledger Cross-Verification Result */}
                    <div
                      data-testid="merchant-vision-verdict"
                      className={`p-3 rounded-xl border space-y-1.5 text-[11px] ${visionResult.status === 'VERIFIED_LEDGER_MATCH'
                        ? 'bg-emerald-950/75 border-emerald-500/80 text-emerald-50'
                        : visionResult.status === 'NEEDS_MANUAL_REVIEW' ||
                          visionResult.status === 'AI_UNAVAILABLE' ||
                          visionResult.status === 'AMBIGUOUS_EXTRACTION'
                          ? 'bg-amber-950/70 border-amber-500/80 text-amber-50'
                          : 'bg-red-950/80 border-red-500/80 text-red-50'
                        }`}
                    >
                      <div className="flex items-center justify-between gap-2 font-bold">
                        <span>2. Kết quả Đối soát Sổ cái ({visionResult.status})</span>
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-black/40">
                          {visionResult.latencyMs}ms
                        </span>
                      </div>
                      <ul className="space-y-0.5 leading-relaxed">
                        {visionResult.reasonsVi.map((r, i) => (
                          <li key={i}>• {r}</li>
                        ))}
                      </ul>
                      {visionResult.warningsVi.length > 0 && (
                        <div className="text-[10px] text-amber-200 space-y-0.5">
                          {visionResult.warningsVi.map((w, i) => (
                            <div key={i}>⚠ {w}</div>
                          ))}
                        </div>
                      )}
                      <div className="font-bold text-amber-300 pt-0.5">
                        Hành động: {visionResult.recommendedNextActionVi}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* 5 Mandatory Merchant Ledger Verification Scenarios (Cases A-E) */}
            <div className="space-y-1.5">
              <div className="text-[11px] font-bold text-slate-300">
                Thử nhanh 5 tình huống Sổ cái tại quầy thu ngân (Cases A–E):
              </div>
              {MERCHANT_RECEIPT_PRESETS.map((p) => (
                <button
                  key={p.id}
                  type="button"
                  onClick={() =>
                    void handleVerifyMerchantReceipt(
                      p.claimedTxId,
                      p.claimedAmountVnd,
                      p.merchantAccountIdOrNumber ?? 'ACC-HOSP-800'
                    )
                  }
                  className={`cursor-pointer w-full text-left px-2.5 py-2 rounded-xl border text-[11px] font-bold transition-colors ${p.tone === 'RED'
                    ? 'bg-slate-900 hover:bg-red-950/50 text-red-200 border-red-500/30'
                    : 'bg-slate-900 hover:bg-emerald-950/50 text-emerald-200 border-emerald-500/30'
                    }`}
                >
                  {p.labelVi}
                </button>
              ))}
            </div>

            {/* Custom Merchant Bill Check Form */}
            <form
              onSubmit={(e) => {
                e.preventDefault();
                void handleVerifyMerchantReceipt(
                  merchClaimedTxId,
                  merchClaimedAmount,
                  merchTargetAccount
                );
              }}
              className="bg-slate-900/90 border border-slate-800 rounded-2xl p-3 space-y-2 text-xs"
            >
              <div>
                <label
                  htmlFor="merch-target-account"
                  className="block text-[11px] text-slate-300 font-bold mb-1"
                >
                  Tài khoản Tiểu thương đối soát (Check người nhận)
                </label>
                <input
                  id="merch-target-account"
                  type="text"
                  value={merchTargetAccount}
                  onChange={(e) => setMerchTargetAccount(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-700 rounded-xl px-2.5 py-1.5 text-cyan-200 font-bold"
                />
              </div>
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label
                    htmlFor="merch-tx-id"
                    className="block text-[11px] text-slate-300 font-bold mb-1"
                  >
                    Mã GD trên ảnh Bill
                  </label>
                  <input
                    id="merch-tx-id"
                    type="text"
                    value={merchClaimedTxId}
                    onChange={(e) => setMerchClaimedTxId(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-700 rounded-xl px-2.5 py-1.5 text-white font-bold"
                  />
                </div>
                <div>
                  <label
                    htmlFor="merch-amount"
                    className="block text-[11px] text-slate-300 font-bold mb-1"
                  >
                    Số tiền ghi trên Bill (₫)
                  </label>
                  <input
                    id="merch-amount"
                    type="number"
                    value={merchClaimedAmount}
                    onChange={(e) => setMerchClaimedAmount(Number(e.target.value) || 0)}
                    className="w-full bg-slate-950 border border-slate-700 rounded-xl px-2.5 py-1.5 text-amber-300 font-bold"
                  />
                </div>
              </div>
              <button
                type="submit"
                disabled={isVerifyingMerchant}
                className="cursor-pointer disabled:opacity-60 w-full py-2 px-3 rounded-xl bg-[#A50064] hover:bg-pink-700 text-white font-bold text-xs flex items-center justify-center gap-1.5"
              >
                {isVerifyingMerchant ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <ReceiptText className="w-4 h-4" />
                )}
                <span>
                  {isVerifyingMerchant
                    ? 'Đang đối soát Sổ cái trên máy chủ...'
                    : 'Đối soát Sổ cái & Kích hoạt Loa MoMo'}
                </span>
              </button>
            </form>

            {merchantErrorVi && (
              <div className="p-2.5 rounded-xl bg-red-950/70 border border-red-500/60 text-red-100 text-[11px] font-semibold">
                {merchantErrorVi}
              </div>
            )}

            {/* Verification Verdict + Loa MoMo Announcement */}
            {merchantResult && (
              <div
                className={`p-3.5 rounded-2xl border space-y-2 text-xs ${merchantResult.verdict === 'VERIFIED_LEDGER_MATCH'
                  ? 'bg-emerald-950/70 border-emerald-500/80 text-emerald-50'
                  : 'bg-red-950/75 border-red-500/80 text-red-50'
                  }`}
              >
                <div className="flex items-center justify-between gap-2 font-bold">
                  <span>{merchantResult.headlineVi}</span>
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-black/40 shrink-0">
                    {merchantResult.responseTimeMs}ms
                  </span>
                </div>
                <p className="leading-relaxed">{merchantResult.explanationVi}</p>
                <div className="p-2.5 rounded-xl bg-slate-950/90 border border-slate-700 space-y-1.5">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-bold text-pink-300 flex items-center gap-1.5">
                      <Volume2 className="w-3.5 h-3.5" />
                      <span>Âm thanh Loa MoMo Soundbox:</span>
                    </span>
                    <button
                      type="button"
                      onClick={() => speakSoundbox(merchantResult.soundboxAnnouncementVi)}
                      className="cursor-pointer px-2 py-0.5 rounded bg-pink-600/30 hover:bg-pink-600/50 text-pink-200 font-bold text-[10px] border border-pink-500/40"
                    >
                      Phát tiếng
                    </button>
                  </div>
                  <div className="italic text-white">
                    &ldquo;{merchantResult.soundboxAnnouncementVi}&rdquo;
                  </div>
                </div>
                <div className="font-bold text-amber-300 pt-0.5">
                  Khuyến nghị: {merchantResult.merchantActionVi}
                </div>
              </div>
            )}
          </div>
        ) : (
          <>
            {/* Active Shield Banner */}
            <div
              className={`p-2.5 rounded-xl border text-xs font-semibold flex items-center gap-2 ${isTargetProtected
                ? 'bg-emerald-500/15 border-emerald-500/40 text-emerald-200'
                : 'bg-amber-500/15 border-amber-500/40 text-amber-200'
                }`}
            >
              {isTargetProtected ? (
                <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
              ) : (
                <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
              )}
              <span>
                {isTargetProtected
                  ? `Lá chắn Aegis Shield ĐANG BẬT cho STK ${recipientAccount} — Bấm chuyển để kiểm chứng chặn!`
                  : `STK ${recipientAccount} chưa có lệnh chặn cứng (Bật từ Playbook hoặc tab Quản trị)`}
              </span>
            </div>

            {/* Victim Self-Rescue Celebration Banner */}
            {selfRescuedDone && (
              <div className="p-3.5 rounded-2xl bg-emerald-950/80 border border-emerald-400 text-emerald-50 space-y-1.5 text-xs">
                <div className="flex items-center gap-2 font-bold text-emerald-300 text-sm">
                  <CheckCircle2 className="w-4 h-4 shrink-0" />
                  <span>Đã hủy giao dịch &amp; Bảo toàn {amountVnd.toLocaleString('vi-VN')} ₫!</span>
                </div>
                <p className="text-emerald-100 leading-relaxed">
                  Tuyệt vời! Bạn đã thoát khỏi bẫy thao túng tâm lý. Số dư ví <strong>{walletBalanceVnd.toLocaleString('vi-VN')} ₫</strong> vẫn an toàn nguyên vẹn và đã ghi nhận vào KPI hệ thống.
                </p>
              </div>
            )}

            {/* Real-time Interception Decision + Psychological De-escalation Card */}
            {lastDecision && !selfRescuedDone && (
              <div
                className={`p-3.5 rounded-2xl border space-y-2.5 ${lastDecision.decision === 'BLOCKED_BY_SHIELD'
                  ? 'bg-red-950/70 border-red-500/80 text-red-50'
                  : lastDecision.decision === 'WARN_COOLING_OFF'
                    ? 'bg-amber-950/60 border-amber-500/80 text-amber-50'
                    : 'bg-emerald-950/60 border-emerald-500/80 text-emerald-50'
                  }`}
              >
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2 text-xs sm:text-sm font-bold">
                    {lastDecision.decision === 'BLOCKED_BY_SHIELD' ? (
                      <AlertOctagon className="w-4 h-4 text-red-400 shrink-0" />
                    ) : lastDecision.decision === 'WARN_COOLING_OFF' ? (
                      <ShieldAlert className="w-4 h-4 text-amber-400 shrink-0" />
                    ) : (
                      <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                    )}
                    <span>
                      {lastDecision.decision === 'BLOCKED_BY_SHIELD'
                        ? 'Giao dịch bị chặn bởi Lá chắn Aegis Shield'
                        : lastDecision.decision === 'WARN_COOLING_OFF'
                          ? 'Cảnh báo làm nguội tâm lý (Smart Cooling-Off)'
                          : 'Giao dịch hợp lệ — Cho phép thực hiện'}
                    </span>
                  </div>
                  <span className="text-[11px] font-bold px-2 py-0.5 rounded bg-black/40 shrink-0">
                    {lastDecision.responseTimeMs}ms
                  </span>
                </div>

                <p className="text-xs leading-relaxed">{lastDecision.explanationVi}</p>

                {lastDecision.transactionId && (
                  <div className="p-2 rounded-xl bg-black/30 border border-white/10 flex flex-wrap items-center justify-between gap-2 text-[11px]">
                    <div>
                      Mã Sổ cái:{' '}
                      <strong className="font-mono text-cyan-300">{lastDecision.transactionId}</strong>{' '}
                      <span className="opacity-80">({lastDecision.transactionStatus ?? 'SETTLED'})</span>
                    </div>
                    <button
                      type="button"
                      onClick={() => {
                        const targetCheck =
                          lastDecision.recipientAccountId ?? lastDecision.recipientAccountNumber;
                        setWalletMode('MERCHANT');
                        void handleVerifyMerchantReceipt(
                          lastDecision.transactionId!,
                          lastDecision.amountVnd,
                          targetCheck
                        );
                      }}
                      className="cursor-pointer px-2 py-0.5 rounded bg-pink-600/30 hover:bg-pink-600/50 text-pink-100 border border-pink-500/40 font-bold"
                    >
                      Đối soát ở Loa Tiểu thương →
                    </button>
                  </div>
                )}

                {lastDecision.deEscalationCardVi && (
                  <div className="bg-slate-950/95 border border-amber-400/40 rounded-xl p-3 space-y-2 text-xs">
                    <div className="flex items-center gap-1.5 font-bold text-amber-300">
                      <HeartHandshake className="w-4 h-4 shrink-0" />
                      <span>Gỡ bùa Thao túng Tâm lý (Bảo vệ Nhân văn):</span>
                    </div>
                    <div className="text-white font-bold">
                      {lastDecision.deEscalationCardVi.archetypeTitleVi}
                    </div>
                    <p className="text-slate-300 leading-relaxed">
                      {lastDecision.deEscalationCardVi.manipulationTacticVi}
                    </p>
                    <ul className="space-y-1 text-emerald-200 pt-1 border-t border-slate-800">
                      {lastDecision.deEscalationCardVi.realityChecklistVi.map((chk, idx) => (
                        <li key={idx} className="flex items-start gap-1.5">
                          <span className="text-emerald-400 font-bold">✓</span>
                          <span>{chk}</span>
                        </li>
                      ))}
                    </ul>
                    <div className="pt-1 flex items-center gap-1.5 font-semibold text-amber-300">
                      <PhoneCall className="w-3.5 h-3.5" />
                      <span>{lastDecision.deEscalationCardVi.emergencyHotlineVi}</span>
                    </div>

                    {/* Victim Self-Rescue Interactive Confirmation */}
                    {onAcknowledgeDeEscalation && (
                      <button
                        type="button"
                        disabled={isAcknowledging}
                        onClick={async () => {
                          setIsAcknowledging(true);
                          try {
                            const ok = await onAcknowledgeDeEscalation({
                              recipientAccount,
                              amountVnd,
                            });
                            if (ok) setSelfRescuedDone(true);
                          } finally {
                            setIsAcknowledging(false);
                          }
                        }}
                        className="cursor-pointer w-full mt-1 py-2 px-3 rounded-xl bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs flex items-center justify-center gap-1.5 shadow"
                      >
                        <ShieldCheck className="w-4 h-4" />
                        <span>
                          {isAcknowledging
                            ? 'Đang hủy lệnh chuyển...'
                            : 'Tôi đã hiểu đây là lừa đảo — Hủy giao dịch & Giữ tiền'}
                        </span>
                      </button>
                    )}
                  </div>
                )}
              </div>
            )}

            {/* Transfer Form with 3-Color Trust Light */}
            <form
              onSubmit={async (e) => {
                e.preventDefault();
                if (isSubmitting) return;
                setIsSubmitting(true);
                setEscalatedSuccess(false);
                setSelfRescuedDone(false);
                try {
                  const res = await onSimulateTransfer({
                    senderAccountId: senderAccount?.id,
                    recipientAccount,
                    amountVnd,
                    message,
                    idempotencyKey: attemptKey,
                  });
                  if (res) refreshAttemptKey();
                } finally {
                  setIsSubmitting(false);
                }
              }}
              className="space-y-2.5 bg-slate-900/90 p-3 rounded-2xl border border-slate-800"
            >
              {/* Quick Recipient Buttons */}
              <div>
                <div className="text-xs font-bold text-slate-300 mb-1.5">
                  Chọn nhanh tài khoản nhận để kiểm thử:
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {[
                    { acc: '1903999888777', label: '1903999888777 (Giả Công an)' },
                    { acc: '1903111222333', label: '1903111222333 (Mule ATO)' },
                    { acc: '1188999000888', label: '1188999000888 (Bệnh viện)' },
                  ].map((item) => (
                    <button
                      key={item.acc}
                      type="button"
                      onClick={() => {
                        setRecipientAccount(item.acc);
                        setSelfRescuedDone(false);
                      }}
                      className={`cursor-pointer text-[11px] font-bold px-2 py-1 rounded-lg border transition-colors ${recipientAccount === item.acc
                        ? 'bg-amber-500/20 text-amber-200 border-amber-400'
                        : 'bg-slate-950 text-slate-300 border-slate-800 hover:text-white'
                        }`}
                    >
                      {item.label}
                    </button>
                  ))}
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                <div>
                  <label
                    htmlFor="wallet-recipient"
                    className="block text-[11px] text-slate-300 font-bold mb-1"
                  >
                    Số tài khoản người nhận
                  </label>
                  <input
                    id="wallet-recipient"
                    type="text"
                    value={recipientAccount}
                    onChange={(e) => {
                      setRecipientAccount(e.target.value);
                      setSelfRescuedDone(false);
                    }}
                    className="w-full bg-slate-950 border border-slate-700 rounded-xl px-2.5 py-1.5 text-xs text-white font-bold"
                  />
                </div>

                <div>
                  <label
                    htmlFor="wallet-amount"
                    className="block text-[11px] text-slate-300 font-bold mb-1"
                  >
                    Số tiền: <strong className="text-amber-400">{amountVnd.toLocaleString('vi-VN')} ₫</strong>
                  </label>
                  <input
                    id="wallet-amount"
                    type="number"
                    value={amountVnd}
                    onChange={(e) => setAmountVnd(Number(e.target.value) || 0)}
                    className="w-full bg-slate-950 border border-slate-700 rounded-xl px-2.5 py-1.5 text-xs text-amber-400 font-bold"
                  />
                </div>
              </div>

              {/* MoMo + A05/SIMO 3-Color Trust Traffic Light */}
              <div
                className={`p-2.5 rounded-xl border text-xs space-y-1 transition-colors ${trustLight.color === 'RED'
                  ? 'bg-red-950/60 border-red-500/70 text-red-100'
                  : trustLight.color === 'YELLOW'
                    ? 'bg-amber-950/45 border-amber-500/60 text-amber-100'
                    : 'bg-emerald-950/45 border-emerald-500/60 text-emerald-100'
                  }`}
              >
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2 font-bold">
                    <span className="inline-flex items-center gap-1 bg-black/40 px-2 py-0.5 rounded-full">
                      <span
                        className={`w-2.5 h-2.5 rounded-full ${trustLight.color === 'GREEN' ? 'bg-emerald-400 shadow-[0_0_8px_#34d399]' : 'bg-slate-700'
                          }`}
                      />
                      <span
                        className={`w-2.5 h-2.5 rounded-full ${trustLight.color === 'YELLOW' ? 'bg-amber-400 shadow-[0_0_8px_#fbbf24]' : 'bg-slate-700'
                          }`}
                      />
                      <span
                        className={`w-2.5 h-2.5 rounded-full ${trustLight.color === 'RED' ? 'bg-red-500 shadow-[0_0_8px_#ef4444]' : 'bg-slate-700'
                          }`}
                      />
                    </span>
                    <span>{trustLight.badgeVi}</span>
                  </div>
                  <span className="text-[10px] font-semibold opacity-80">{trustLight.sourceTag}</span>
                </div>
                <div className="font-bold">{trustLight.headlineVi}</div>
                <div className="text-[11px] opacity-90">{trustLight.detailVi}</div>
              </div>

              <div>
                <label
                  htmlFor="wallet-msg"
                  className="block text-[11px] text-slate-300 font-bold mb-1"
                >
                  Nội dung chuyển tiền
                </label>
                <input
                  id="wallet-msg"
                  type="text"
                  value={message}
                  onChange={(e) => setMessage(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-700 rounded-xl px-2.5 py-1.5 text-xs text-slate-100"
                />
              </div>

              <button
                type="submit"
                disabled={isSubmitting}
                className="cursor-pointer w-full py-2.5 px-4 rounded-xl bg-amber-500 hover:bg-amber-400 text-slate-950 font-bold text-xs flex items-center justify-center gap-2 shadow-sm transition-colors"
              >
                <span>Xác nhận Chuyển {amountVnd.toLocaleString('vi-VN')} ₫</span>
                <ArrowRight className="w-4 h-4" />
              </button>

              {onEscalateToOps && (
                <button
                  type="button"
                  disabled={isEscalating}
                  onClick={async () => {
                    setIsEscalating(true);
                    try {
                      const ok = await onEscalateToOps({
                        recipientAccount,
                        amountVnd,
                        message,
                      });
                      if (ok) setEscalatedSuccess(true);
                    } finally {
                      setIsEscalating(false);
                    }
                  }}
                  className="cursor-pointer w-full py-2 px-3 rounded-xl bg-slate-950 hover:bg-slate-800 text-slate-200 border border-slate-700 text-xs font-bold flex items-center justify-center gap-1.5 transition-colors"
                >
                  <SendToBack className="w-3.5 h-3.5 text-violet-400" />
                  <span>
                    {isEscalating
                      ? 'Đang gửi cảnh báo về AegisOps...'
                      : 'Báo cáo Nghi lừa đảo lên Bàn làm việc AegisOps'}
                  </span>
                </button>
              )}

              {escalatedSuccess && (
                <div className="p-2 rounded-lg bg-emerald-500/15 border border-emerald-500/40 text-xs text-emerald-200 text-center">
                  Đã đẩy vụ việc mới từ Ví lên Hàng đợi AegisOps và kích hoạt AI Điều tra!
                </div>
              )}
            </form>

            {/* 1-Click & Raw TLV VietQR Scanner */}
            <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-3 space-y-2">
              <div className="flex items-center justify-between gap-2">
                <div className="text-xs font-bold text-white flex items-center gap-1.5">
                  <QrCode className="w-4 h-4 text-cyan-400" />
                  <span>Quét Mã VietQR (EMVCo TLV &amp; NAPAS Name-Check):</span>
                </div>
                <button
                  type="button"
                  onClick={() => setShowRawQrTester((v) => !v)}
                  className="cursor-pointer text-[11px] font-bold text-cyan-300 hover:text-cyan-200"
                >
                  {showRawQrTester ? 'Ẩn chuỗi Raw TLV' : 'Tự nhập Raw TLV'}
                </button>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                <button
                  type="button"
                  onClick={() => void handleScanVietQr('QR-SPOOF-GHN')}
                  className="cursor-pointer text-left text-[11px] px-2.5 py-2 rounded-xl bg-slate-950 hover:bg-slate-800 text-red-200 border border-red-500/30 font-bold transition-colors"
                >
                  Quét QR Giả mạo &ldquo;Hoàn tiền GHN&rdquo;
                </button>
                <button
                  type="button"
                  onClick={() => void handleScanVietQr('QR-HOSPITAL-SAFE')}
                  className="cursor-pointer text-left text-[11px] px-2.5 py-2 rounded-xl bg-slate-950 hover:bg-slate-800 text-emerald-200 border border-emerald-500/30 font-bold transition-colors"
                >
                  Quét QR Bệnh viện Quốc tế Hợp lệ
                </button>
              </div>

              {showRawQrTester && (
                <div className="bg-slate-950 border border-slate-800 rounded-xl p-2.5 space-y-2 text-[11px]">
                  <div>
                    <label
                      htmlFor="qr-raw-brand"
                      className="block text-slate-400 mb-0.5 font-semibold"
                    >
                      Tên thương hiệu in trên biển QR:
                    </label>
                    <input
                      id="qr-raw-brand"
                      type="text"
                      value={rawQrBrandInput}
                      onChange={(e) => setRawQrBrandInput(e.target.value)}
                      className="w-full bg-slate-900 border border-slate-700 rounded-lg px-2 py-1 text-white"
                    />
                  </div>
                  <div>
                    <label
                      htmlFor="qr-raw-payload"
                      className="block text-slate-400 mb-0.5 font-semibold"
                    >
                      Chuỗi EMVCo VietQR Payload (TLV):
                    </label>
                    <textarea
                      id="qr-raw-payload"
                      rows={2}
                      value={rawQrPayloadInput}
                      onChange={(e) => setRawQrPayloadInput(e.target.value)}
                      className="w-full bg-slate-900 border border-slate-700 rounded-lg px-2 py-1 text-amber-200 font-semibold"
                    />
                  </div>
                  <button
                    type="button"
                    onClick={async () => {
                      const parsed = parseRawEmvVietQrPayload({
                        rawPayload: rawQrPayloadInput,
                        displayedBrandName: rawQrBrandInput,
                      });
                      setQrScanResult(parsed);
                      setRecipientAccount(parsed.recipientAccountNumber);
                      setAmountVnd(parsed.amountVnd);
                      setMessage(parsed.transferMessage);
                      await onSimulateTransfer({
                        senderAccountId: senderAccount?.id,
                        recipientAccount: parsed.recipientAccountNumber,
                        amountVnd: parsed.amountVnd,
                        message: parsed.transferMessage,
                        idempotencyKey: attemptKey,
                      });
                      refreshAttemptKey();
                    }}
                    className="cursor-pointer w-full py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold"
                  >
                    Giải mã TLV EMVCo &amp; Kiểm tra NAPAS Ngay
                  </button>
                </div>
              )}

              {qrScanResult && (
                <div
                  className={`p-2.5 rounded-xl border text-xs space-y-1 ${qrScanResult.nameMismatchDetected
                    ? 'bg-red-950/70 border-red-500/50 text-red-100'
                    : 'bg-emerald-950/60 border-emerald-500/40 text-emerald-100'
                    }`}
                >
                  <div className="font-bold">
                    {qrScanResult.nameMismatchDetected
                      ? 'Phát hiện tráo mã VietQR (Sai lệch tên đơn vị thụ hưởng)'
                      : 'Mã VietQR động hợp lệ (Khớp tên đăng ký NAPAS)'}
                  </div>
                  <div>
                    Tên in trên ảnh QR: <strong>{qrScanResult.displayedBrandName}</strong>
                  </div>
                  <div>
                    Chủ TK thực tế tại NAPAS:{' '}
                    <strong className="text-amber-300">{qrScanResult.napasLegalOwnerName}</strong>
                  </div>
                </div>
              )}
            </div>
          </>
        )}
      </div>

      {/* Bottom Smartphone Home Indicator */}
      <div className="bg-slate-950 py-2 flex items-center justify-center border-t border-slate-900 shrink-0">
        <div className="w-28 h-1 rounded-full bg-slate-700" />
      </div>
    </aside>
  );

  if (isSplitDocked) {
    return walletCard;
  }

  return (
    <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center sm:justify-end p-4">
      {walletCard}
    </div>
  );
};
