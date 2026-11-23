'use client';

import { useState } from 'react';
import {
  Lock,
  PauseCircle,
  PlayCircle,
  PlusCircle,
  QrCode,
  ShieldAlert,
  ShieldCheck,
  Smartphone,
} from 'lucide-react';
import type { MerchantBillVerificationResult } from '@/domain/merchant-verifier';
import type {
  Account,
  ConsumerTransferDecision,
  MerchantVisionVerificationBundle,
  ShieldRule,
  Transaction,
} from '@/domain/types';
import { ConsumerWalletSimulator } from './ConsumerWalletSimulator';

interface WalletShieldWorkspaceViewProps {
  prefillAccount: string;
  prefillAmount: number;
  activeShieldRules: ShieldRule[];
  frozenAccountIds: string[];
  accounts: Account[];
  transactions?: Transaction[];
  lastDecision: ConsumerTransferDecision | null;
  canManageShieldRules?: boolean;
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
  onToggleShieldRule?: (ruleId: string) => Promise<boolean>;
  onAddCustomShieldRule?: (params: {
    targetAccountNumber: string;
    targetOwnerName?: string;
    reasonVi?: string;
  }) => Promise<boolean>;
  onEscalateToOps: (params: {
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
  onBackToInvestigation: () => void;
}

export const WalletShieldWorkspaceView = ({
  prefillAccount,
  prefillAmount,
  activeShieldRules,
  frozenAccountIds,
  accounts,
  transactions = [],
  lastDecision,
  canManageShieldRules = true,
  onSimulateTransfer,
  onAcknowledgeDeEscalation,
  onToggleShieldRule,
  onAddCustomShieldRule,
  onEscalateToOps,
  onVerifyMerchantReceipt,
  onVerifyMerchantVision,
  onBackToInvestigation,
}: WalletShieldWorkspaceViewProps) => {
  const [newAcc, setNewAcc] = useState('');
  const [newOwner, setNewOwner] = useState('');
  const [addingRule, setAddingRule] = useState(false);

  return (
    <div className="grid grid-cols-1 xl:grid-cols-12 gap-4 items-start">
      {/* Left: Authentic Mobile Phone Consumer Wallet Frame */}
      <div className="xl:col-span-5 flex justify-center">
        <div className="w-full max-w-md">
          <ConsumerWalletSimulator
            isOpen={true}
            isSplitDocked={true}
            prefillAccount={prefillAccount}
            prefillAmount={prefillAmount}
            activeShieldRules={activeShieldRules}
            accounts={accounts}
            transactions={transactions}
            lastDecision={lastDecision}
            onClose={onBackToInvestigation}
            onSimulateTransfer={onSimulateTransfer}
            onAcknowledgeDeEscalation={onAcknowledgeDeEscalation}
            onEscalateToOps={onEscalateToOps}
            onVerifyMerchantReceipt={onVerifyMerchantReceipt}
            onVerifyMerchantVision={onVerifyMerchantVision}
          />
        </div>
      </div>

      {/* Right: Interactive Shield Governance (Pause / Resume / Add Custom Block Rule) */}
      <div className="xl:col-span-7 space-y-4">
        <section className="bg-slate-900/90 border border-slate-800 rounded-2xl p-4 space-y-3 shadow-lg">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              <h2 className="text-sm font-bold text-white">
                Quản trị Quy tắc Lá chắn Cộng đồng ({activeShieldRules.filter((r) => r.active).length}/{activeShieldRules.length} đang bật)
              </h2>
            </div>
            <span className="text-xs font-bold px-2.5 py-0.5 rounded-lg bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
              Bật / Tạm dừng để so sánh Trước &amp; Sau
            </span>
          </div>

          {/* Quick Add Custom Block Rule Form (L2 Checker Only) */}
          {onAddCustomShieldRule && canManageShieldRules && (
            <form
              onSubmit={async (e) => {
                e.preventDefault();
                if (!newAcc.trim()) return;
                setAddingRule(true);
                try {
                  const ok = await onAddCustomShieldRule({
                    targetAccountNumber: newAcc.trim(),
                    targetOwnerName: newOwner.trim() || undefined,
                  });
                  if (ok) {
                    setNewAcc('');
                    setNewOwner('');
                  }
                } finally {
                  setAddingRule(false);
                }
              }}
              className="grid grid-cols-1 sm:grid-cols-12 gap-2 bg-slate-950 p-3 rounded-xl border border-slate-800 text-xs"
            >
              <input
                type="text"
                value={newAcc}
                onChange={(e) => setNewAcc(e.target.value)}
                placeholder="Nhập STK cần chặn khẩn (VD: 1903777666555)..."
                className="sm:col-span-5 bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-white font-bold"
              />
              <input
                type="text"
                value={newOwner}
                onChange={(e) => setNewOwner(e.target.value)}
                placeholder="Tên chủ TK (tùy chọn)..."
                className="sm:col-span-4 bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-white"
              />
              <button
                type="submit"
                disabled={addingRule || !newAcc.trim()}
                className="sm:col-span-3 cursor-pointer inline-flex items-center justify-center gap-1.5 px-3 py-1.5 rounded-lg bg-amber-500 hover:bg-amber-400 text-slate-950 font-bold disabled:opacity-50"
              >
                <PlusCircle className="w-3.5 h-3.5" />
                <span>{addingRule ? 'Đang thêm...' : 'Thêm Luật Chặn'}</span>
              </button>
            </form>
          )}

          {activeShieldRules.length === 0 ? (
            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-xs text-slate-300 space-y-2">
              <div className="font-bold text-amber-300 flex items-center gap-1.5">
                <ShieldAlert className="w-4 h-4" />
                <span>Chưa có Lá chắn nào được kích hoạt.</span>
              </div>
              <p className="text-slate-400 leading-relaxed">
                Bạn có thể nhập trực tiếp STK vào ô bên trên để tạo luật chặn, hoặc bấm <strong>B3: Duyệt Playbook</strong> ở Trung tâm Điều tra để kích hoạt Lá chắn Cộng đồng cho vụ <code>ALT-APP-003</code>.
              </p>
              <button
                type="button"
                onClick={onBackToInvestigation}
                className="cursor-pointer px-3 py-1.5 rounded-xl bg-amber-500 hover:bg-amber-400 text-slate-950 font-bold"
              >
                Mở Trung tâm Điều tra để Duyệt Playbook →
              </button>
            </div>
          ) : (
            <div className="space-y-2.5">
              {activeShieldRules.map((rule) => (
                <div
                  key={rule.id}
                  className={`p-3.5 rounded-xl bg-slate-950 border space-y-1.5 text-xs transition-colors ${
                    rule.active ? 'border-emerald-500/40' : 'border-slate-700 opacity-75'
                  }`}
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className={`font-bold ${rule.active ? 'text-emerald-300' : 'text-slate-400'}`}>
                      {rule.id} • Chặn STK {rule.targetAccountNumber}
                    </span>

                    <div className="flex items-center gap-2">
                      <span
                        className={`px-2 py-0.5 rounded-md font-bold ${
                          rule.active
                            ? 'bg-emerald-500/20 text-emerald-200'
                            : 'bg-amber-500/20 text-amber-200'
                        }`}
                      >
                        {rule.active ? 'Đang bảo vệ' : 'Đang tạm dừng'}
                      </span>
                      {onToggleShieldRule && canManageShieldRules && (
                        <button
                          type="button"
                          onClick={() => void onToggleShieldRule(rule.id)}
                          className={`cursor-pointer inline-flex items-center gap-1 px-2.5 py-1 rounded-lg font-bold border transition-colors ${
                            rule.active
                              ? 'bg-slate-900 hover:bg-slate-800 text-amber-300 border-slate-700'
                              : 'bg-emerald-500 hover:bg-emerald-400 text-slate-950 border-emerald-400'
                          }`}
                        >
                          {rule.active ? (
                            <>
                              <PauseCircle className="w-3.5 h-3.5" />
                              <span>Tạm dừng</span>
                            </>
                          ) : (
                            <>
                              <PlayCircle className="w-3.5 h-3.5" />
                              <span>Bật lại</span>
                            </>
                          )}
                        </button>
                      )}
                    </div>
                  </div>
                  <div className="text-white font-semibold">
                    Chủ TK bị chặn: {rule.targetOwnerName} (Nguồn: {rule.alertId})
                  </div>
                  <p className="text-slate-300 leading-relaxed">{rule.userWarningVi}</p>
                </div>
              ))}
            </div>
          )}
        </section>

        <section className="bg-slate-900/90 border border-slate-800 rounded-2xl p-4 space-y-3 shadow-lg">
          <div className="flex items-center gap-2">
            <Lock className="w-4 h-4 text-red-400" />
            <h3 className="text-sm font-bold text-white">
              Tài khoản Đang bị Phong tỏa ({frozenAccountIds.length})
            </h3>
          </div>
          {frozenAccountIds.length === 0 ? (
            <p className="text-xs text-slate-400">
              Chưa có tài khoản Mule nào bị phong tỏa trong phiên làm việc này.
            </p>
          ) : (
            <div className="flex flex-wrap gap-2">
              {frozenAccountIds.map((id) => (
                <span
                  key={id}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-red-500/15 text-red-200 border border-red-500/40 text-xs font-bold"
                >
                  <Lock className="w-3.5 h-3.5" />
                  <span>{id}</span>
                </span>
              ))}
            </div>
          )}

          <div className="pt-2 border-t border-slate-800 grid grid-cols-1 sm:grid-cols-2 gap-2.5 text-xs">
            <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-1">
              <div className="font-bold text-cyan-300 flex items-center gap-1.5">
                <Smartphone className="w-3.5 h-3.5" />
                <span>Đèn Tín nhiệm 3 Màu (Mô phỏng)</span>
              </div>
              <p className="text-slate-400 leading-relaxed">
                Đối chiếu STK người nhận với danh sách lá chắn cục bộ (mô phỏng luồng cảnh báo A05/SIMO, không kết nối mạng ngoài).
              </p>
            </div>
            <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-1">
              <div className="font-bold text-amber-300 flex items-center gap-1.5">
                <QrCode className="w-3.5 h-3.5" />
                <span>Kiểm tra VietQR EMVCo (Mô phỏng)</span>
              </div>
              <p className="text-slate-400 leading-relaxed">
                Giải mã cấu trúc EMVCo TLV cục bộ và đối chiếu tên hiển thị với danh mục tài khoản mô phỏng (chưa tích hợp NAPAS thực).
              </p>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
};
