'use client';

import { useEffect, useMemo, useState } from 'react';
import {
  Command,
  FileCheck2,
  FilePlus2,
  LayoutDashboard,
  Lock,
  Play,
  RotateCcw,
  Search,
  SearchCode,
  ShieldAlert,
  Smartphone,
  Sparkles,
  UserCog,
  X,
} from 'lucide-react';
import type { FraudAlert, OperatorRole } from '@/domain/types';
import type { WorkspaceViewId } from './AppShellSidebar';

interface CommandItem {
  id: string;
  groupVi: string;
  labelVi: string;
  hintVi: string;
  icon: React.ReactNode;
  run: () => void;
}

interface CommandPaletteModalProps {
  isOpen: boolean;
  alerts: FraudAlert[];
  operatorRole: OperatorRole;
  onClose: () => void;
  onSelectView: (view: WorkspaceViewId) => void;
  onSelectAlertAndInspect: (alertId: string) => void;
  onRunInvestigation: () => void;
  onApprovePlaybook: () => void;
  onOpenWallet: () => void;
  onRunAutoDemo: () => void;
  onChangeRole: (role: OperatorRole) => void;
  onResetDemo: () => void;
}

export const CommandPaletteModal = ({
  isOpen,
  alerts,
  operatorRole,
  onClose,
  onSelectView,
  onSelectAlertAndInspect,
  onRunInvestigation,
  onApprovePlaybook,
  onOpenWallet,
  onRunAutoDemo,
  onChangeRole,
  onResetDemo,
}: CommandPaletteModalProps) => {
  const [query, setQuery] = useState('');
  const [activeIndex, setActiveIndex] = useState(0);

  useEffect(() => {
    if (isOpen) {
      setQuery('');
      setActiveIndex(0);
    }
  }, [isOpen]);

  const commands: CommandItem[] = useMemo(() => {
    const baseCommands: CommandItem[] = [
      {
        id: 'nav-dashboard',
        groupVi: 'Điều hướng Phân hệ',
        labelVi: 'Mở Dashboard Tổng quan (KPI, Biểu đồ & CSV)',
        hintVi: 'View 1',
        icon: <LayoutDashboard className="w-4 h-4 text-amber-400" />,
        run: () => onSelectView('DASHBOARD'),
      },
      {
        id: 'nav-investigation',
        groupVi: 'Điều hướng Phân hệ',
        labelVi: 'Mở Trung tâm Điều tra Đa nguồn & Sơ đồ BFS',
        hintVi: 'View 2',
        icon: <SearchCode className="w-4 h-4 text-cyan-400" />,
        run: () => onSelectView('INVESTIGATION'),
      },
      {
        id: 'nav-builder',
        groupVi: 'Điều hướng Phân hệ',
        labelVi: 'Mở Biểu mẫu Nhập Hồ sơ 4 Phần & Vision OCR',
        hintVi: 'View 3',
        icon: <FilePlus2 className="w-4 h-4 text-violet-400" />,
        run: () => onSelectView('CASE_BUILDER'),
      },
      {
        id: 'nav-wallet',
        groupVi: 'Điều hướng Phân hệ',
        labelVi: 'Mở Mô phỏng Ví MoMo & Quản trị Lá chắn',
        hintVi: 'View 4',
        icon: <Smartphone className="w-4 h-4 text-emerald-400" />,
        run: () => onSelectView('WALLET_SHIELD'),
      },
      {
        id: 'nav-compliance',
        groupVi: 'Điều hướng Phân hệ',
        labelVi: 'Mở Hồ sơ Pháp lý NHNN (QĐ 2345 / SIMO) & Nhật ký',
        hintVi: 'View 5',
        icon: <FileCheck2 className="w-4 h-4 text-rose-400" />,
        run: () => onSelectView('COMPLIANCE_AUDIT'),
      },
      {
        id: 'act-investigate',
        groupVi: 'Thao tác Điều tra Nhanh',
        labelVi: 'Chạy AI Điều tra Gemini cho vụ đang chọn',
        hintVi: 'Bước 2',
        icon: <Sparkles className="w-4 h-4 text-violet-400" />,
        run: () => {
          onSelectView('INVESTIGATION');
          onRunInvestigation();
        },
      },
      {
        id: 'act-playbook',
        groupVi: 'Thao tác Điều tra Nhanh',
        labelVi: 'Duyệt Playbook & Kích hoạt Lá chắn Cộng đồng',
        hintVi: 'Bước 3',
        icon: <Lock className="w-4 h-4 text-amber-400" />,
        run: () => {
          onSelectView('INVESTIGATION');
          onApprovePlaybook();
        },
      },
      {
        id: 'act-wallet-modal',
        groupVi: 'Thao tác Điều tra Nhanh',
        labelVi: 'Mở nhanh Điện thoại Ví MoMo để Test Chặn',
        hintVi: 'Bước 4',
        icon: <Smartphone className="w-4 h-4 text-emerald-400" />,
        run: onOpenWallet,
      },
      {
        id: 'act-auto-demo',
        groupVi: 'Thao tác Điều tra Nhanh',
        labelVi: 'Chạy Trình diễn Tự động Khép kín (15 giây)',
        hintVi: 'Auto Demo',
        icon: <Play className="w-4 h-4 text-amber-400" />,
        run: onRunAutoDemo,
      },
      {
        id: 'act-toggle-role',
        groupVi: 'Phân quyền & Hệ thống',
        labelVi:
          operatorRole === 'L2_CHECKER'
            ? 'Chuyển sang quyền Chuyên viên L1 (Maker)'
            : 'Chuyển sang quyền Quản lý Rủi ro L2 (Checker)',
        hintVi: 'Maker-Checker',
        icon: <UserCog className="w-4 h-4 text-cyan-400" />,
        run: () => onChangeRole(operatorRole === 'L2_CHECKER' ? 'L1_MAKER' : 'L2_CHECKER'),
      },
      {
        id: 'act-reset',
        groupVi: 'Phân quyền & Hệ thống',
        labelVi: 'Đặt lại toàn bộ dữ liệu gốc (Reset Workspace)',
        hintVi: 'Reset',
        icon: <RotateCcw className="w-4 h-4 text-slate-300" />,
        run: onResetDemo,
      },
    ];

    const alertCommands: CommandItem[] = alerts.map((a) => ({
      id: `alert-${a.id}`,
      groupVi: 'Nhảy thẳng tới Vụ việc',
      labelVi: `${a.id} — ${a.title}`,
      hintVi: `Rủi ro ${a.deterministicRiskScore}/100`,
      icon: <ShieldAlert className="w-4 h-4 text-red-400" />,
      run: () => onSelectAlertAndInspect(a.id),
    }));

    return [...baseCommands, ...alertCommands];
  }, [
    alerts,
    onApprovePlaybook,
    onChangeRole,
    onOpenWallet,
    onResetDemo,
    onRunAutoDemo,
    onRunInvestigation,
    onSelectAlertAndInspect,
    onSelectView,
    operatorRole,
  ]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return commands;
    return commands.filter(
      (c) =>
        c.labelVi.toLowerCase().includes(q) ||
        c.groupVi.toLowerCase().includes(q) ||
        c.hintVi.toLowerCase().includes(q)
    );
  }, [commands, query]);

  if (!isOpen) return null;

  const executeItem = (item: CommandItem | undefined) => {
    if (!item) return;
    item.run();
    onClose();
  };

  return (
    <div
      onClick={onClose}
      className="fixed inset-0 z-50 bg-slate-950/85 backdrop-blur-sm flex items-start justify-center pt-16 px-4"
    >
      <div
        onClick={(e) => e.stopPropagation()}
        className="w-full max-w-2xl bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl overflow-hidden flex flex-col"
      >
        <div className="px-4 py-3 bg-slate-950 border-b border-slate-800 flex items-center gap-2.5">
          <Command className="w-4 h-4 text-amber-400 shrink-0" />
          <Search className="w-4 h-4 text-slate-400 shrink-0" />
          <input
            type="text"
            autoFocus
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setActiveIndex(0);
            }}
            onKeyDown={(e) => {
              if (e.key === 'ArrowDown') {
                e.preventDefault();
                setActiveIndex((prev) => Math.min(filtered.length - 1, prev + 1));
              } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                setActiveIndex((prev) => Math.max(0, prev - 1));
              } else if (e.key === 'Enter') {
                e.preventDefault();
                executeItem(filtered[activeIndex]);
              } else if (e.key === 'Escape') {
                onClose();
              }
            }}
            placeholder="Gõ tên phân hệ, mã vụ việc (ALT-...), hoặc hành động..."
            className="flex-1 bg-transparent text-sm text-white placeholder:text-slate-400 focus:outline-none"
          />
          <button
            type="button"
            onClick={onClose}
            aria-label="Đóng Command Palette"
            className="cursor-pointer p-1 rounded-lg hover:bg-slate-800 text-slate-400"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="max-h-96 overflow-y-auto p-2 space-y-1">
          {filtered.length === 0 ? (
            <div className="py-8 text-center text-xs text-slate-400">
              Không tìm thấy lệnh hoặc vụ việc khớp với &ldquo;{query}&rdquo;.
            </div>
          ) : (
            filtered.map((item, idx) => {
              const selected = idx === activeIndex;
              return (
                <button
                  key={item.id}
                  type="button"
                  onMouseEnter={() => setActiveIndex(idx)}
                  onClick={() => executeItem(item)}
                  className={`cursor-pointer w-full px-3 py-2.5 rounded-xl flex items-center justify-between gap-3 text-left text-xs transition-colors ${
                    selected
                      ? 'bg-amber-500/20 border border-amber-400/60 text-white'
                      : 'border border-transparent hover:bg-slate-800/60 text-slate-200'
                  }`}
                >
                  <div className="flex items-center gap-2.5 min-w-0">
                    {item.icon}
                    <div className="min-w-0">
                      <div className="font-bold truncate">{item.labelVi}</div>
                      <div className="text-[11px] text-slate-400">{item.groupVi}</div>
                    </div>
                  </div>
                  <span className="text-[11px] font-bold px-2 py-0.5 rounded-md bg-slate-950 text-slate-300 border border-slate-800 shrink-0">
                    {item.hintVi}
                  </span>
                </button>
              );
            })
          )}
        </div>

        <div className="px-4 py-2 bg-slate-950 border-t border-slate-800 flex items-center justify-between text-[11px] text-slate-400">
          <span>Dùng ↑ ↓ để chọn • Enter để thực thi</span>
          <span>ESC để đóng</span>
        </div>
      </div>
    </div>
  );
};
