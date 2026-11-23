'use client';

import { AlertTriangle, CheckCircle2, Info, ShieldAlert, X } from 'lucide-react';
import type { WorkspaceNotification } from '@/domain/types';

interface ToastNotificationStackProps {
  toasts: WorkspaceNotification[];
  onDismiss: (id: string) => void;
}

export const ToastNotificationStack = ({
  toasts,
  onDismiss,
}: ToastNotificationStackProps) => {
  if (toasts.length === 0) return null;

  return (
    <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 max-w-sm w-full pointer-events-none">
      {toasts.map((t) => {
        const styleCfg =
          t.severity === 'CRITICAL'
            ? 'bg-red-950/95 border-red-500/70 text-red-50'
            : t.severity === 'WARNING'
              ? 'bg-amber-950/95 border-amber-500/70 text-amber-50'
              : t.severity === 'SUCCESS'
                ? 'bg-emerald-950/95 border-emerald-500/70 text-emerald-50'
                : 'bg-slate-900/95 border-cyan-500/60 text-slate-100';

        const Icon =
          t.severity === 'CRITICAL'
            ? ShieldAlert
            : t.severity === 'WARNING'
              ? AlertTriangle
              : t.severity === 'SUCCESS'
                ? CheckCircle2
                : Info;

        return (
          <div
            key={t.id}
            className={`pointer-events-auto p-3.5 rounded-xl border shadow-2xl backdrop-blur flex items-start gap-2.5 text-xs animate-in fade-in slide-in-from-bottom-2 ${styleCfg}`}
          >
            <Icon className="w-4 h-4 shrink-0 mt-0.5" />
            <div className="flex-1 min-w-0">
              <div className="font-bold leading-snug">{t.titleVi}</div>
              <p className="text-[11px] opacity-90 mt-0.5 leading-relaxed">{t.detailVi}</p>
            </div>
            <button
              type="button"
              onClick={() => onDismiss(t.id)}
              aria-label="Đóng thông báo"
              className="cursor-pointer p-1 rounded hover:bg-black/20 shrink-0"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        );
      })}
    </div>
  );
};
