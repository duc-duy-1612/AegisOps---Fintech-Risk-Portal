'use client';

import { useState } from 'react';
import {
  Bell,
  Command,
  Play,
  Search,
  ShieldAlert,
  Smartphone,
  X,
} from 'lucide-react';
import type { OperatorRole, WorkspaceNotification } from '@/domain/types';
import type { WorkspaceViewId } from './AppShellSidebar';

export type CaseTagFilterId =
  | 'ALL'
  | 'MULTIMODAL_APP_FRAUD'
  | 'CYBER_ATO_MULE'
  | 'BUSINESS_LOGIC_RACE'
  | 'SMART_FALSE_POSITIVE'
  | 'CUSTOM_SANDBOX'
  | 'STATUS_PENDING'
  | 'STATUS_RESOLVED';

export interface TagFilterOption {
  id: CaseTagFilterId;
  labelVi: string;
  count: number;
  toneClass: string;
}

interface WorkspaceCommandHeaderProps {
  activeView: WorkspaceViewId;
  operatorRole: OperatorRole;
  searchQuery: string;
  selectedTagFilter?: CaseTagFilterId;
  tagOptions?: TagFilterOption[];
  notifications: WorkspaceNotification[];
  currentGuidedStep?: 1 | 2 | 3;
  walletPrefillAccount?: string;
  activeShieldCount: number;
  isAutoDemoRunning: boolean;
  isInvestigating?: boolean;
  isApprovingPlaybook?: boolean;
  onSearchChange: (q: string) => void;
  onSelectTagFilter?: (tag: CaseTagFilterId) => void;
  onSelectView?: (view: WorkspaceViewId) => void;
  onOpenWalletModal: () => void;
  onRunAutoDemo: () => void;
  onRunInvestigation?: () => void;
  onApprovePlaybook?: () => void;
  onMarkAllRead: () => void;
  onOpenCommandPalette?: () => void;
}

const VIEW_TITLES: Record<WorkspaceViewId, { titleVi: string; descVi: string }> = {
  DASHBOARD: {
    titleVi: 'Tổng quan Vận hành',
    descVi: 'Phát hiện lừa đảo chuyển tiền & chặn tài khoản rác theo thời gian thực',
  },
  INVESTIGATION: {
    titleVi: 'Trung tâm Điều tra',
    descVi: 'Đồ thị dòng tiền BFS, 5 công cụ định lượng & Trợ lý Gemini có kiểm định trích dẫn',
  },
  CASE_BUILDER: {
    titleVi: 'Nhập Hồ sơ Kiểm thử',
    descVi: 'Tự tạo kịch bản mô phỏng 4 phần hoặc tải ảnh mẫu OCR (chỉ dùng dữ liệu giả lập)',
  },
  WALLET_SHIELD: {
    titleVi: 'Ví MoMo & Lá chắn Người dùng',
    descVi: 'Kiểm chứng chặn chuyển tiền vào tài khoản rác, đèn 3 màu & đối soát Bill tiểu thương',
  },
  COMPLIANCE_AUDIT: {
    titleVi: 'Pháp lý & Nhật ký Audit',
    descVi: 'Đối chiếu QĐ 2345, TT 50/77, Luật 91/2025 & xuất biên bản SIMO ẩn danh PII',
  },
};

const ROLE_PILL_LABELS: Record<OperatorRole, { labelVi: string; toneClass: string }> = {
  L2_CHECKER: {
    labelVi: 'L2 Checker',
    toneClass: 'bg-amber-500/10 text-amber-300 border-amber-500/25',
  },
  L1_MAKER: {
    labelVi: 'L1 Maker',
    toneClass: 'bg-cyan-500/10 text-cyan-300 border-cyan-500/25',
  },
  END_USER: {
    labelVi: 'Người dùng Ví',
    toneClass: 'bg-emerald-500/10 text-emerald-300 border-emerald-500/25',
  },
};

export const WorkspaceCommandHeader = ({
  activeView,
  operatorRole,
  searchQuery,
  notifications,
  activeShieldCount,
  isAutoDemoRunning,
  onSearchChange,
  onOpenWalletModal,
  onRunAutoDemo,
  onMarkAllRead,
  onOpenCommandPalette,
}: WorkspaceCommandHeaderProps) => {
  const [showNotifDropdown, setShowNotifDropdown] = useState(false);
  const viewInfo = VIEW_TITLES[activeView];
  const rolePill = ROLE_PILL_LABELS[operatorRole];
  const unreadCount = notifications.filter((n) => !n.read).length;

  return (
    <header className="border-b border-slate-800/80 bg-slate-950/95 backdrop-blur sticky top-0 z-20">
      {/* Slim Synthetic-Only Contest Boundary Notice (preserved for compliance & tests) */}
      <div
        data-testid="synthetic-env-notice"
        className="px-4 py-1 bg-amber-950/40 border-b border-amber-500/20 flex items-center gap-2 text-[11px] text-amber-200/90"
      >
        <ShieldAlert className="w-3.5 h-3.5 text-amber-400 shrink-0" />
        <span className="truncate">
          <strong className="text-amber-300">Môi trường Mô phỏng (Synthetic Contest Demo):</strong>{' '}
          Chỉ dùng dữ liệu giả lập — không nhập CCCD, SĐT, STK hay ảnh giao dịch thật.
        </span>
      </div>

      {/* Single Clean Primary Command Bar */}
      <div className="px-4 py-2.5 flex flex-wrap xl:flex-nowrap items-center justify-between gap-2.5 sm:gap-3">
        <div className="w-full xl:w-auto xl:flex-1 min-w-0">
          <div className="flex items-center gap-2 min-w-0">
            <h1 className="text-sm sm:text-base font-bold text-white truncate">
              {viewInfo.titleVi}
            </h1>
            <span
              className={`text-[11px] font-semibold px-2 py-0.5 rounded-md border hidden sm:inline-block shrink-0 ${rolePill.toneClass}`}
            >
              {rolePill.labelVi}
            </span>
          </div>
          <p className="text-xs text-slate-400 truncate mt-0.5">{viewInfo.descVi}</p>
        </div>

        {/* Focused Right Controls: Search, Shortcut, Bell, Wallet Preview, Single Primary CTA */}
        <div className="flex items-center gap-2 w-full xl:w-auto justify-end min-w-0 xl:shrink-0">
          {(activeView === 'DASHBOARD' || activeView === 'INVESTIGATION') && (
            <div className="relative flex-1 min-w-0 xl:flex-none xl:w-60">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => onSearchChange(e.target.value)}
                placeholder="Tìm mã vụ, STK..."
                className="w-full bg-slate-900/90 border border-slate-800 focus:border-amber-400/80 rounded-xl pl-8 pr-7 py-1.5 text-xs text-white placeholder:text-slate-500 focus:outline-none transition-colors"
              />
              {searchQuery && (
                <button
                  type="button"
                  onClick={() => onSearchChange('')}
                  aria-label="Xóa tìm kiếm"
                  className="cursor-pointer absolute right-2 top-1/2 -translate-y-1/2 text-slate-400 hover:text-white"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              )}
            </div>
          )}

          {onOpenCommandPalette && (
            <button
              type="button"
              onClick={onOpenCommandPalette}
              title="Mở bảng Lệnh nhanh (Ctrl + K)"
              className="cursor-pointer hidden lg:inline-flex items-center gap-1 px-2.5 py-1.5 rounded-xl text-[11px] font-semibold bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 transition-colors whitespace-nowrap"
            >
              <Command className="w-3 h-3 text-slate-400" />
              <span>Ctrl+K</span>
            </button>
          )}

          {/* Notification Bell */}
          <div className="relative">
            <button
              type="button"
              onClick={() => setShowNotifDropdown((v) => !v)}
              aria-label="Trung tâm Thông báo"
              className="cursor-pointer relative p-2 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 hover:text-white transition-colors"
            >
              <Bell className="w-4 h-4 text-slate-300" />
              {unreadCount > 0 && (
                <span className="absolute -top-1 -right-1 min-w-[16px] h-4 px-1 rounded-full bg-red-500 text-white text-[10px] font-bold flex items-center justify-center">
                  {unreadCount}
                </span>
              )}
            </button>

            {showNotifDropdown && (
              <div className="absolute right-0 mt-2 w-80 sm:w-96 bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl p-3 space-y-2 z-50">
                <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                  <span className="text-xs font-bold text-white">
                    Thông báo ({notifications.length})
                  </span>
                  <button
                    type="button"
                    onClick={() => {
                      onMarkAllRead();
                      setShowNotifDropdown(false);
                    }}
                    className="cursor-pointer text-[11px] font-semibold text-cyan-300 hover:text-cyan-200"
                  >
                    Đánh dấu đã đọc
                  </button>
                </div>
                <div className="max-h-72 overflow-y-auto space-y-1.5 pr-0.5">
                  {notifications.map((n) => (
                    <div
                      key={n.id}
                      className={`p-2.5 rounded-xl border text-xs ${
                        n.read
                          ? 'bg-slate-950/60 border-slate-800/80 text-slate-300'
                          : 'bg-slate-950 border-amber-500/40 text-white'
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-bold">{n.titleVi}</span>
                        <span suppressHydrationWarning className="text-[10px] text-slate-400 shrink-0">
                          {new Date(n.timestamp).toLocaleTimeString('vi-VN')}
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-300 mt-0.5">{n.detailVi}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          <button
            type="button"
            onClick={onOpenWalletModal}
            className="cursor-pointer hidden sm:inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-800 transition-colors whitespace-nowrap"
          >
            <Smartphone className="w-3.5 h-3.5 text-emerald-400" />
            <span>Ví MoMo</span>
            {activeShieldCount > 0 && (
              <span className="px-1.5 py-0 rounded-md bg-emerald-500/20 text-emerald-300 text-[10px] font-bold">
                {activeShieldCount}
              </span>
            )}
          </button>

          <button
            type="button"
            disabled={isAutoDemoRunning}
            onClick={onRunAutoDemo}
            className="cursor-pointer inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-xl text-xs font-bold bg-amber-500 hover:bg-amber-400 disabled:opacity-60 text-slate-950 transition-colors whitespace-nowrap shadow-sm"
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            <span>{isAutoDemoRunning ? 'Đang chạy Demo...' : 'Chạy Demo 15s'}</span>
          </button>
        </div>
      </div>
    </header>
  );
};
