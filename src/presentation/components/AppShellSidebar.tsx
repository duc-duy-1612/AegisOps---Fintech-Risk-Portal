'use client';

import { useEffect, useState } from 'react';
import {
  ChevronLeft,
  ChevronRight,
  Columns2,
  FileCheck2,
  FilePlus2,
  LayoutDashboard,
  Play,
  Radio,
  RotateCcw,
  SearchCode,
  ShieldAlert,
  ShieldCheck,
  Sliders,
  Smartphone,
  UserCog,
} from 'lucide-react';
import type { OperatorRole } from '@/domain/types';

export type WorkspaceViewId =
  | 'DASHBOARD'
  | 'INVESTIGATION'
  | 'CASE_BUILDER'
  | 'WALLET_SHIELD'
  | 'COMPLIANCE_AUDIT';

interface AppShellSidebarProps {
  activeView: WorkspaceViewId;
  collapsed: boolean;
  operatorRole: OperatorRole;
  alertCount: number;
  pendingCount: number;
  activeShieldCount: number;
  auditCount: number;
  isSplitScreen: boolean;
  showPendingOnly: boolean;
  isLiveFeedEnabled: boolean;
  isAutoDemoRunning: boolean;
  sessionId: string;
  onSelectView: (view: WorkspaceViewId) => void;
  onChangeRole: (role: OperatorRole) => void;
  onToggleCollapse: () => void;
  onToggleSplitScreen: () => void;
  onTogglePendingOnly: () => void;
  onToggleLiveFeed: () => void;
  onRunAutoDemo: () => void;
  onResetDemo: () => void;
}

export const AppShellSidebar = ({
  activeView,
  collapsed,
  operatorRole,
  alertCount,
  pendingCount,
  activeShieldCount,
  auditCount,
  isSplitScreen,
  showPendingOnly,
  isLiveFeedEnabled,
  isAutoDemoRunning,
  sessionId,
  onSelectView,
  onChangeRole,
  onToggleCollapse,
  onToggleSplitScreen,
  onTogglePendingOnly,
  onToggleLiveFeed,
  onRunAutoDemo,
  onResetDemo,
}: AppShellSidebarProps) => {
  const [aiHealthState, setAiHealthState] = useState<{
    status: 'loading' | 'live_gemini' | 'deterministic_fallback' | 'unavailable';
    modelLabel: string;
  }>({ status: 'loading', modelLabel: 'Đang kiểm tra AI...' });

  useEffect(() => {
    const controller = new AbortController();
    let mounted = true;
    fetch('/api/health', { signal: controller.signal })
      .then(async (res) => {
        if (!res.ok) throw new Error('Health unavailable');
        return (await res.json()) as {
          aiEngineReady?: boolean;
          primaryModel?: string;
        };
      })
      .then((data) => {
        if (!mounted) return;
        if (data.aiEngineReady) {
          setAiHealthState({
            status: 'live_gemini',
            modelLabel: `${data.primaryModel || 'Gemini'} Live`,
          });
        } else {
          setAiHealthState({
            status: 'deterministic_fallback',
            modelLabel: 'Deterministic Fallback',
          });
        }
      })
      .catch(() => {
        if (!mounted) return;
        setAiHealthState({
          status: 'unavailable',
          modelLabel: 'AI Health Unavailable',
        });
      });

    return () => {
      mounted = false;
      controller.abort();
    };
  }, []);

  const navItems: {
    id: WorkspaceViewId;
    labelVi: string;
    subtitleVi: string;
    badge?: string | number;
    badgeColor?: string;
    icon: React.ReactNode;
  }[] = [
    {
      id: 'DASHBOARD',
      labelVi: 'Dashboard Tổng quan',
      subtitleVi: 'KPI, Biểu đồ & Tag Box',
      badge: `${alertCount}`,
      badgeColor: 'bg-slate-800 text-slate-200',
      icon: <LayoutDashboard className="w-4 h-4 text-amber-400 shrink-0" />,
    },
    {
      id: 'INVESTIGATION',
      labelVi: 'Trung tâm Điều tra',
      subtitleVi: 'Đồ thị, Bằng chứng & AI',
      badge: pendingCount > 0 ? `${pendingCount} chờ` : 'Xong',
      badgeColor:
        pendingCount > 0
          ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
          : 'bg-emerald-500/20 text-emerald-300',
      icon: <SearchCode className="w-4 h-4 text-cyan-400 shrink-0" />,
    },
    {
      id: 'CASE_BUILDER',
      labelVi: 'Nhập Hồ sơ Kiểm thử',
      subtitleVi: 'Form 4 Phần & Vision OCR',
      badge: 'Mới',
      badgeColor: 'bg-violet-500/20 text-violet-300 border border-violet-500/30',
      icon: <FilePlus2 className="w-4 h-4 text-violet-400 shrink-0" />,
    },
    {
      id: 'WALLET_SHIELD',
      labelVi: 'Ví & Lá chắn Người dùng',
      subtitleVi: 'Đèn 3 Màu, VietQR & Chặn',
      badge: activeShieldCount,
      badgeColor:
        activeShieldCount > 0
          ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
          : 'bg-slate-800 text-slate-300',
      icon: <Smartphone className="w-4 h-4 text-emerald-400 shrink-0" />,
    },
    {
      id: 'COMPLIANCE_AUDIT',
      labelVi: 'Pháp lý & Nhật ký Audit',
      subtitleVi: 'QĐ 2345, TT 50 & SIMO',
      badge: auditCount,
      badgeColor: 'bg-slate-800 text-slate-300',
      icon: <FileCheck2 className="w-4 h-4 text-rose-400 shrink-0" />,
    },
  ];

  return (
    <aside
      className={`bg-slate-950 border-r border-slate-800/90 flex flex-col justify-between shrink-0 transition-all duration-200 ${
        collapsed ? 'w-[72px]' : 'w-64'
      }`}
    >
      {/* Top Brand + Primary Vertical Menu */}
      <div className="p-3 space-y-4">
        {/* Brand Row */}
        <div className="flex items-center justify-between gap-2 pb-3 border-b border-slate-800/80">
          <div className="flex items-center gap-2.5 min-w-0">
            <div className="h-9 w-9 rounded-xl bg-amber-500/15 border border-amber-500/40 flex items-center justify-center text-amber-400 shrink-0">
              <ShieldAlert className="w-5 h-5" />
            </div>
            {!collapsed && (
              <div className="min-w-0">
                <div className="text-sm font-bold text-white truncate">AegisOps</div>
                <div className="text-[11px] font-semibold text-emerald-400 truncate">
                  Fintech Risk Portal
                </div>
              </div>
            )}
          </div>

          <button
            type="button"
            onClick={onToggleCollapse}
            title={collapsed ? 'Mở rộng Menu dọc' : 'Thu gọn Menu dọc'}
            className="cursor-pointer p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-white border border-slate-800 shrink-0"
          >
            {collapsed ? (
              <ChevronRight className="w-3.5 h-3.5" />
            ) : (
              <ChevronLeft className="w-3.5 h-3.5" />
            )}
          </button>
        </div>

        {/* Navigation Section */}
        <div className="space-y-1">
          {!collapsed && (
            <div className="px-2 pb-1 text-[11px] font-bold text-slate-400">
              Menu Phân hệ Chính
            </div>
          )}
          <nav aria-label="Menu dọc AegisOps" className="space-y-1">
            {navItems.map((item) => {
              const isActive = activeView === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => onSelectView(item.id)}
                  title={collapsed ? item.labelVi : undefined}
                  className={`cursor-pointer w-full flex items-center justify-between gap-2 px-2.5 py-2.5 rounded-xl border text-left transition-all ${
                    isActive
                      ? 'bg-slate-800/95 border-amber-400/70 text-white shadow-sm'
                      : 'bg-transparent border-transparent hover:bg-slate-900 text-slate-300 hover:text-white'
                  }`}
                >
                  <div className="flex items-center gap-2.5 min-w-0">
                    {item.icon}
                    {!collapsed && (
                      <div className="min-w-0">
                        <div className="text-xs font-bold truncate">{item.labelVi}</div>
                        <div className="text-[11px] text-slate-400 truncate">{item.subtitleVi}</div>
                      </div>
                    )}
                  </div>
                  {!collapsed && item.badge !== undefined && (
                    <span
                      className={`text-[10px] font-bold px-1.5 py-0.5 rounded-md shrink-0 ${item.badgeColor}`}
                    >
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>
        </div>

        {/* Vertical Quick Toggles & Feature Options */}
        <div className="pt-3 border-t border-slate-800/80 space-y-1.5">
          {!collapsed && (
            <div className="px-2 pb-1 text-[11px] font-bold text-slate-400 flex items-center gap-1.5">
              <Sliders className="w-3 h-3 text-cyan-400" />
              <span>Tùy chọn Chức năng Dọc</span>
            </div>
          )}

          <button
            type="button"
            onClick={onToggleSplitScreen}
            title="Bật/Tắt xem Song song Điều tra & Ví"
            className={`cursor-pointer w-full flex items-center justify-between gap-2 px-2.5 py-2 rounded-xl border text-xs font-bold transition-colors ${
              isSplitScreen
                ? 'bg-cyan-500/15 border-cyan-500/40 text-cyan-200'
                : 'bg-slate-900/70 border-slate-800 text-slate-300 hover:text-white'
            }`}
          >
            <span className="flex items-center gap-2 truncate">
              <Columns2 className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
              {!collapsed && <span className="truncate">Xem Song song Ví</span>}
            </span>
            {!collapsed && (
              <span
                className={`w-7 h-4 rounded-full p-0.5 transition-colors flex items-center ${
                  isSplitScreen ? 'bg-cyan-500 justify-end' : 'bg-slate-700 justify-start'
                }`}
              >
                <span className="w-3 h-3 rounded-full bg-white" />
              </span>
            )}
          </button>

          <button
            type="button"
            onClick={onTogglePendingOnly}
            title="Lọc chỉ hiển thị vụ việc đang chờ duyệt"
            className={`cursor-pointer w-full flex items-center justify-between gap-2 px-2.5 py-2 rounded-xl border text-xs font-bold transition-colors ${
              showPendingOnly
                ? 'bg-amber-500/15 border-amber-500/40 text-amber-200'
                : 'bg-slate-900/70 border-slate-800 text-slate-300 hover:text-white'
            }`}
          >
            <span className="flex items-center gap-2 truncate">
              <ShieldCheck className="w-3.5 h-3.5 text-amber-400 shrink-0" />
              {!collapsed && <span className="truncate">Chỉ lọc Ca Chờ duyệt</span>}
            </span>
            {!collapsed && (
              <span
                className={`w-7 h-4 rounded-full p-0.5 transition-colors flex items-center ${
                  showPendingOnly ? 'bg-amber-500 justify-end' : 'bg-slate-700 justify-start'
                }`}
              >
                <span className="w-3 h-3 rounded-full bg-white" />
              </span>
            )}
          </button>

          <button
            type="button"
            onClick={onToggleLiveFeed}
            title="Bật/Tắt luồng cảnh báo Real-time"
            className={`cursor-pointer w-full flex items-center justify-between gap-2 px-2.5 py-2 rounded-xl border text-xs font-bold transition-colors ${
              isLiveFeedEnabled
                ? 'bg-emerald-500/15 border-emerald-500/40 text-emerald-200'
                : 'bg-slate-900/70 border-slate-800 text-slate-300 hover:text-white'
            }`}
          >
            <span className="flex items-center gap-2 truncate">
              <Radio
                className={`w-3.5 h-3.5 shrink-0 ${
                  isLiveFeedEnabled ? 'text-emerald-400 animate-pulse' : 'text-slate-400'
                }`}
              />
              {!collapsed && <span className="truncate">Luồng Cảnh báo Live</span>}
            </span>
            {!collapsed && (
              <span
                className={`w-7 h-4 rounded-full p-0.5 transition-colors flex items-center ${
                  isLiveFeedEnabled ? 'bg-emerald-500 justify-end' : 'bg-slate-700 justify-start'
                }`}
              >
                <span className="w-3 h-3 rounded-full bg-white" />
              </span>
            )}
          </button>

          {/* Banking Maker-Checker Demo Persona Selector */}
          {!collapsed && (
            <div className="pt-2 space-y-1">
              <label
                htmlFor="sidebar-role-select"
                className="px-1 text-[11px] font-bold text-slate-400 flex items-center gap-1.5"
              >
                <UserCog className="w-3.5 h-3.5 text-violet-400" />
                <span>Chế độ Giả lập Vai trò Demo (Maker-Checker):</span>
              </label>
              <select
                id="sidebar-role-select"
                value={operatorRole}
                onChange={(e) => onChangeRole(e.target.value as OperatorRole)}
                className="w-full bg-slate-900 border border-slate-700 rounded-xl px-2.5 py-1.5 text-xs font-bold text-white"
              >
                <option value="L2_CHECKER">Quản lý Rủi ro L2 (Checker)</option>
                <option value="L1_MAKER">Chuyên viên L1 (Maker)</option>
                <option value="END_USER">Khách hàng Ví (End-User)</option>
              </select>
              <p className="px-1 text-[10px] text-slate-400 leading-snug">
                Mô phỏng 1-Click cho Demo cuộc thi (khóa bằng{' '}
                <code className="text-slate-300">AEGIS_ENABLE_DEMO_PERSONA_SWITCH=false</code> ở
                Production; không thay thế SSO doanh nghiệp).
              </p>
            </div>
          )}

          <button
            type="button"
            disabled={isAutoDemoRunning}
            onClick={onRunAutoDemo}
            title="Trình diễn Tự động Khép kín 15 giây"
            className="cursor-pointer w-full flex items-center gap-2 px-2.5 py-2 rounded-xl bg-amber-500 hover:bg-amber-400 text-slate-950 text-xs font-bold transition-colors"
          >
            <Play className="w-3.5 h-3.5 fill-current shrink-0" />
            {!collapsed && <span className="truncate">Trình diễn Tự động (15s)</span>}
          </button>

          <button
            type="button"
            onClick={onResetDemo}
            title="Khôi phục dữ liệu mẫu ban đầu"
            className="cursor-pointer w-full flex items-center gap-2 px-2.5 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 hover:text-white text-xs font-bold transition-colors"
          >
            <RotateCcw className="w-3.5 h-3.5 text-slate-400 shrink-0" />
            {!collapsed && <span className="truncate">Đặt lại Dữ liệu Gốc</span>}
          </button>
        </div>
      </div>

      {/* Bottom Engine Status Footer */}
      <div className="p-3 border-t border-slate-800/80">
        {collapsed ? (
          <div
            title={`${aiHealthState.modelLabel} • Session: ${sessionId}`}
            className={`w-9 h-9 mx-auto rounded-xl border flex items-center justify-center ${
              aiHealthState.status === 'live_gemini'
                ? 'bg-emerald-500/15 border-emerald-500/30'
                : aiHealthState.status === 'deterministic_fallback'
                  ? 'bg-amber-500/15 border-amber-500/30'
                  : 'bg-slate-900 border-slate-700'
            }`}
          >
            <span
              className={`w-2.5 h-2.5 rounded-full ${
                aiHealthState.status === 'live_gemini'
                  ? 'bg-emerald-400 animate-pulse'
                  : aiHealthState.status === 'deterministic_fallback'
                    ? 'bg-amber-400'
                    : aiHealthState.status === 'loading'
                      ? 'bg-slate-400 animate-pulse'
                      : 'bg-red-400'
              }`}
            />
          </div>
        ) : (
          <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-2.5 space-y-1">
            <div
              className={`flex items-center justify-between text-xs font-bold ${
                aiHealthState.status === 'live_gemini'
                  ? 'text-emerald-300'
                  : aiHealthState.status === 'deterministic_fallback'
                    ? 'text-amber-300'
                    : aiHealthState.status === 'loading'
                      ? 'text-slate-300'
                      : 'text-red-300'
              }`}
            >
              <span className="flex items-center gap-1.5 truncate">
                <span
                  className={`w-2 h-2 rounded-full shrink-0 ${
                    aiHealthState.status === 'live_gemini'
                      ? 'bg-emerald-400 animate-pulse'
                      : aiHealthState.status === 'deterministic_fallback'
                        ? 'bg-amber-400'
                        : aiHealthState.status === 'loading'
                          ? 'bg-slate-400 animate-pulse'
                          : 'bg-red-400'
                  }`}
                />
                <span className="truncate">{aiHealthState.modelLabel}</span>
              </span>
              <span className="text-[10px] text-slate-400 shrink-0">Định lượng gốc</span>
            </div>
            <div className="text-[11px] text-slate-400 truncate">
              Phiên: <span className="text-slate-200 font-semibold">{sessionId}</span>
            </div>
          </div>
        )}
      </div>
    </aside>
  );
};
