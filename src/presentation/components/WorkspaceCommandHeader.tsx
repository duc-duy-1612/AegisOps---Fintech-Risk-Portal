'use client';

import { useState } from 'react';
import {
  Bell,
  CheckCircle2,
  Command,
  FilePlus2,
  Lock,
  Play,
  Search,
  ShieldAlert,
  Smartphone,
  Sparkles,
  Tag,
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
  selectedTagFilter: CaseTagFilterId;
  tagOptions: TagFilterOption[];
  notifications: WorkspaceNotification[];
  currentGuidedStep: 1 | 2 | 3;
  walletPrefillAccount: string;
  activeShieldCount: number;
  isAutoDemoRunning: boolean;
  isInvestigating: boolean;
  isApprovingPlaybook: boolean;
  onSearchChange: (q: string) => void;
  onSelectTagFilter: (tag: CaseTagFilterId) => void;
  onSelectView: (view: WorkspaceViewId) => void;
  onOpenWalletModal: () => void;
  onRunAutoDemo: () => void;
  onRunInvestigation: () => void;
  onApprovePlaybook: () => void;
  onMarkAllRead: () => void;
  onOpenCommandPalette?: () => void;
}

const VIEW_TITLES: Record<WorkspaceViewId, { titleVi: string; descVi: string }> = {
  DASHBOARD: {
    titleVi: 'Dashboard Tổng quan Điều hành & Giám sát Gian lận',
    descVi: 'Theo dõi chỉ số bảo vệ tài sản thời gian thực, lọc vụ việc theo Tag Box & điều hướng nhanh',
  },
  INVESTIGATION: {
    titleVi: 'Trung tâm Điều tra Đa nguồn & Sơ đồ Dòng tiền',
    descVi: 'Đồ thị BFS tương tác, 5 công cụ định lượng & Trợ lý AI có kiểm định tham chiếu trích dẫn',
  },
  CASE_BUILDER: {
    titleVi: 'Xưởng Nhập Hồ sơ & Kịch bản Mô phỏng (Form 4 Phần)',
    descVi: 'Tự nhập thông số kịch bản mô phỏng (tài khoản, thiết bị, API & ảnh mẫu) — không nhập dữ liệu thật',
  },
  WALLET_SHIELD: {
    titleVi: 'Mô phỏng Ví MoMo & Quản trị Lá chắn Cộng đồng',
    descVi: 'Đèn tín nhiệm 3 màu, giải mã VietQR EMVCo cục bộ & Lá chắn Ví mô phỏng',
  },
  COMPLIANCE_AUDIT: {
    titleVi: 'Hồ sơ Pháp lý & Nhật ký Kiểm toán Hệ thống',
    descVi: 'Đối chiếu QĐ 2345, TT 50/2024 (sửa bởi TT 77/2025), Luật 91/2025 & SIMO giả danh PII mô phỏng',
  },
};

const ROLE_PILL_LABELS: Record<OperatorRole, { labelVi: string; toneClass: string }> = {
  L2_CHECKER: {
    labelVi: 'L2 Checker (Toàn quyền)',
    toneClass: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
  },
  L1_MAKER: {
    labelVi: 'L1 Maker (Chỉ đề xuất)',
    toneClass: 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30',
  },
  END_USER: {
    labelVi: 'Người dùng Ví MoMo',
    toneClass: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
  },
};

export const WorkspaceCommandHeader = ({
  activeView,
  operatorRole,
  searchQuery,
  selectedTagFilter,
  tagOptions,
  notifications,
  currentGuidedStep,
  walletPrefillAccount,
  activeShieldCount,
  isAutoDemoRunning,
  isInvestigating,
  isApprovingPlaybook,
  onSearchChange,
  onSelectTagFilter,
  onSelectView,
  onOpenWalletModal,
  onRunAutoDemo,
  onRunInvestigation,
  onApprovePlaybook,
  onMarkAllRead,
  onOpenCommandPalette,
}: WorkspaceCommandHeaderProps) => {
  const [showNotifDropdown, setShowNotifDropdown] = useState(false);
  const viewInfo = VIEW_TITLES[activeView];
  const rolePill = ROLE_PILL_LABELS[operatorRole];
  const unreadCount = notifications.filter((n) => !n.read).length;

  return (
    <header className="border-b border-slate-800/90 bg-slate-950/95 backdrop-blur sticky top-0 z-20">
      {/* Synthetic-Only Contest Environment Boundary Notice (B1.0.3) */}
      <div
        data-testid="synthetic-env-notice"
        className="px-4 py-1.5 bg-amber-950/55 border-b border-amber-500/30 flex items-center gap-2 text-[11px] text-amber-200"
      >
        <ShieldAlert className="w-3.5 h-3.5 text-amber-400 shrink-0" />
        <span className="leading-snug">
          <strong className="text-amber-300">Môi trường Mô phỏng (Synthetic Contest Demo):</strong>{' '}
          Chỉ sử dụng dữ liệu giả lập — <strong>KHÔNG</strong> nhập thông tin cá nhân (CCCD, SĐT, STK), tài khoản ngân hàng, hoặc ảnh chụp giao dịch thật.
        </span>
      </div>

      {/* Row 1: Breadcrumb + Role Badge + Search Bar + Notification Bell + Quick Tools */}
      <div className="px-4 py-2.5 flex flex-wrap lg:flex-nowrap items-center justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2 text-xs">
            <span className="text-slate-400 font-semibold">AegisOps Portal</span>
            <span className="text-slate-600">/</span>
            <h1 className="text-sm font-bold text-white truncate">{viewInfo.titleVi}</h1>
            <span
              className={`text-[11px] font-bold px-2 py-0.5 rounded-md border hidden sm:inline-block shrink-0 ${rolePill.toneClass}`}
            >
              {rolePill.labelVi}
            </span>
          </div>
          <p className="text-[11px] text-slate-400 truncate mt-0.5">{viewInfo.descVi}</p>
        </div>

        {/* Search Input + Notification Bell + Quick Horizontal Command Buttons */}
        <div className="flex flex-wrap sm:flex-nowrap items-center gap-2 w-full lg:w-auto justify-end">
          <div className="relative flex-1 sm:w-56">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => onSearchChange(e.target.value)}
              placeholder="Tìm mã vụ, STK, tên chủ TK..."
              className="w-full bg-slate-900 border border-slate-700/80 focus:border-amber-400 rounded-xl pl-8 pr-7 py-1.5 text-xs text-white placeholder:text-slate-400 focus:outline-none"
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

          {onOpenCommandPalette && (
            <button
              type="button"
              onClick={onOpenCommandPalette}
              title="Mở bảng Lệnh nhanh (Ctrl + K)"
              className="cursor-pointer hidden sm:inline-flex items-center gap-1 px-2.5 py-1.5 rounded-xl text-[11px] font-bold bg-slate-900 hover:bg-slate-800 text-amber-300 border border-slate-700 transition-colors whitespace-nowrap"
            >
              <Command className="w-3 h-3" />
              <span>Ctrl+K</span>
            </button>
          )}

          {/* Real-time Notification Bell */}
          <div className="relative">
            <button
              type="button"
              onClick={() => setShowNotifDropdown((v) => !v)}
              aria-label="Trung tâm Thông báo"
              className="cursor-pointer relative p-2 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-200 transition-colors"
            >
              <Bell className="w-4 h-4 text-amber-400" />
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
                    Trung tâm Thông báo Thời gian thực ({notifications.length})
                  </span>
                  <button
                    type="button"
                    onClick={() => {
                      onMarkAllRead();
                      setShowNotifDropdown(false);
                    }}
                    className="cursor-pointer text-[11px] font-bold text-cyan-300 hover:text-cyan-200"
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
            onClick={() => onSelectView('CASE_BUILDER')}
            className="cursor-pointer inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-bold bg-violet-600 hover:bg-violet-500 text-white shadow-sm transition-colors whitespace-nowrap"
          >
            <FilePlus2 className="w-3.5 h-3.5" />
            <span>+ Nhập Hồ sơ Mới</span>
          </button>

          <button
            type="button"
            onClick={onOpenWalletModal}
            className="cursor-pointer inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-bold bg-slate-900 hover:bg-slate-800 text-emerald-300 border border-slate-700 transition-colors whitespace-nowrap"
          >
            <Smartphone className="w-3.5 h-3.5 text-emerald-400" />
            <span>Ví MoMo ({activeShieldCount} Lá chắn)</span>
          </button>

          <button
            type="button"
            disabled={isAutoDemoRunning}
            onClick={onRunAutoDemo}
            className="cursor-pointer inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-bold bg-amber-500 hover:bg-amber-400 text-slate-950 transition-colors whitespace-nowrap"
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            <span>{isAutoDemoRunning ? 'Đang chạy Demo...' : 'Demo 15s'}</span>
          </button>
        </div>
      </div>

      {/* Row 2: Horizontal Tag Box Filter Strip + Compact 4-Step Action Bar */}
      <div className="bg-slate-900/90 border-t border-slate-800/80 px-4 py-1.5 flex flex-wrap items-center justify-between gap-2">
        {/* Tag Box Filter Bar */}
        <div className="flex items-center gap-1.5 overflow-x-auto pb-0.5 max-w-full">
          <span className="text-[11px] font-bold text-slate-400 flex items-center gap-1 shrink-0 mr-1">
            <Tag className="w-3 h-3 text-amber-400" />
            <span>Tag Box:</span>
          </span>
          {tagOptions.map((tag) => {
            const active = selectedTagFilter === tag.id;
            return (
              <button
                key={tag.id}
                type="button"
                onClick={() => onSelectTagFilter(tag.id)}
                className={`cursor-pointer shrink-0 inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[11px] font-bold border transition-all ${
                  active
                    ? 'bg-amber-500 text-slate-950 border-amber-400 shadow-sm'
                    : `${tag.toneClass} hover:border-slate-600`
                }`}
              >
                <span>{tag.labelVi}</span>
                <span
                  className={`px-1.5 py-0 rounded text-[10px] ${
                    active ? 'bg-slate-950/20 text-slate-950' : 'bg-slate-950/80 text-slate-300'
                  }`}
                >
                  {tag.count}
                </span>
              </button>
            );
          })}
        </div>

        {/* Compact Interactive 4-Step Guided Flow */}
        <div className="hidden xl:flex items-center gap-1 text-[11px] shrink-0">
          <button
            type="button"
            onClick={() => onSelectView('CASE_BUILDER')}
            className="cursor-pointer px-2 py-1 rounded-lg font-bold bg-slate-950 hover:bg-slate-800 text-slate-300 border border-slate-800"
          >
            B1: Nhập/Chọn ca
          </button>
          <span className="text-slate-600">→</span>
          <button
            type="button"
            disabled={isInvestigating}
            onClick={() => {
              onSelectView('INVESTIGATION');
              onRunInvestigation();
            }}
            className={`cursor-pointer px-2 py-1 rounded-lg font-bold flex items-center gap-1 ${
              currentGuidedStep === 1
                ? 'bg-violet-600 text-white'
                : 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30'
            }`}
          >
            {currentGuidedStep > 1 ? (
              <CheckCircle2 className="w-3 h-3" />
            ) : (
              <Sparkles className="w-3 h-3" />
            )}
            <span>B2: AI Điều tra</span>
          </button>
          <span className="text-slate-600">→</span>
          <button
            type="button"
            disabled={isApprovingPlaybook}
            onClick={() => {
              onSelectView('INVESTIGATION');
              onApprovePlaybook();
            }}
            className={`cursor-pointer px-2 py-1 rounded-lg font-bold flex items-center gap-1 ${
              currentGuidedStep === 2
                ? 'bg-amber-500 text-slate-950'
                : currentGuidedStep > 2
                  ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30'
                  : 'bg-slate-950 text-slate-300 border border-slate-800'
            }`}
          >
            <Lock className="w-3 h-3" />
            <span>B3: Duyệt Playbook</span>
          </button>
          <span className="text-slate-600">→</span>
          <button
            type="button"
            onClick={onOpenWalletModal}
            className={`cursor-pointer px-2 py-1 rounded-lg font-bold flex items-center gap-1 ${
              currentGuidedStep === 3
                ? 'bg-emerald-500 text-slate-950'
                : 'bg-slate-950 text-slate-300 border border-slate-800'
            }`}
          >
            <Smartphone className="w-3 h-3" />
            <span>B4: Chặn {walletPrefillAccount}</span>
          </button>
        </div>
      </div>
    </header>
  );
};
