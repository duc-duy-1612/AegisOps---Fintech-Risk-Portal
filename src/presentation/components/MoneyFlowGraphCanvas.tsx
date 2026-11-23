'use client';

import { useMemo, useState } from 'react';
import {
  Background,
  Controls,
  MarkerType,
  ReactFlow,
  type Edge,
  type Node,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import {
  Cpu,
  ExternalLink,
  GitBranch,
  Maximize2,
  Minimize2,
  ShieldAlert,
  Smartphone,
  User,
} from 'lucide-react';
import type { GraphEdgeItem, GraphNodeItem } from '@/domain/types';

interface MoneyFlowGraphCanvasProps {
  alertId: string;
  nodes: GraphNodeItem[];
  edges: GraphEdgeItem[];
  frozenAccountIds: string[];
  onSelectEvidenceId: (evidenceId: string) => void;
  onTestNodeInWallet?: (accountIdOrNumber: string) => void;
}

type GraphLayerFilter = 'ALL' | 'MONEY_ONLY' | 'INFRA_ONLY';

const NODE_KIND_VI: Record<GraphNodeItem['nodeKind'], string> = {
  VICTIM: 'Người gửi / Khách hàng',
  SUSPECT_MULE: 'Tài khoản nhận nghi vấn',
  SHARED_DEVICE: 'Thiết bị / IP dùng chung',
  API_ENDPOINT: 'Cổng API bị tấn công',
  TRUSTED_PARTNER: 'Đơn vị thụ hưởng uy tín',
};

const NODE_COLORS: Record<
  GraphNodeItem['riskLevel'],
  { border: string; bg: string; badge: string }
> = {
  CRITICAL: {
    border: '#EF4444',
    bg: '#1F1629',
    badge: 'text-red-200 bg-red-500/25 border border-red-500/40',
  },
  HIGH: {
    border: '#F59E0B',
    bg: '#1E293B',
    badge: 'text-amber-200 bg-amber-500/25 border border-amber-500/40',
  },
  MEDIUM: {
    border: '#06B6D4',
    bg: '#0F172A',
    badge: 'text-cyan-200 bg-cyan-500/20 border border-cyan-500/30',
  },
  SAFE: {
    border: '#10B981',
    bg: '#064E3B',
    badge: 'text-emerald-200 bg-emerald-500/25 border border-emerald-500/40',
  },
};

export const MoneyFlowGraphCanvas = ({
  alertId,
  nodes,
  edges,
  frozenAccountIds,
  onSelectEvidenceId,
  onTestNodeInWallet,
}: MoneyFlowGraphCanvasProps) => {
  const [selectedNode, setSelectedNode] = useState<GraphNodeItem | null>(null);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [layerFilter, setLayerFilter] = useState<GraphLayerFilter>('ALL');

  const visibleEdges = useMemo(() => {
    if (layerFilter === 'MONEY_ONLY') {
      return edges.filter((e) => e.edgeKind === 'MONEY_FLOW');
    }
    if (layerFilter === 'INFRA_ONLY') {
      return edges.filter((e) => e.edgeKind !== 'MONEY_FLOW');
    }
    return edges;
  }, [edges, layerFilter]);

  const visibleNodeIds = useMemo(() => {
    if (layerFilter === 'ALL') return new Set(nodes.map((n) => n.id));
    const ids = new Set<string>();
    visibleEdges.forEach((e) => {
      ids.add(e.source);
      ids.add(e.target);
    });
    return ids.size > 0 ? ids : new Set(nodes.map((n) => n.id));
  }, [layerFilter, nodes, visibleEdges]);

  const flowNodes: Node[] = useMemo(() => {
    return nodes
      .filter((n) => visibleNodeIds.has(n.id))
      .map((n) => {
        const styleCfg = NODE_COLORS[n.riskLevel];
        const isFrozen = frozenAccountIds.includes(n.id);
        const spacedPosition = {
          x: n.position.x * 1.18,
          y: n.position.y * 1.15,
        };

        return {
          id: n.id,
          position: spacedPosition,
          data: {
            label: (
              <div className="text-left p-1.5 space-y-1 font-sans">
                <div className="flex items-center justify-between gap-1.5">
                  <span className={`text-[11px] px-2 py-0.5 rounded-md font-semibold ${styleCfg.badge}`}>
                    {NODE_KIND_VI[n.nodeKind]}
                  </span>
                  {isFrozen && (
                    <span className="text-[11px] px-2 py-0.5 rounded-md bg-emerald-500 text-slate-950 font-bold">
                      Đã phong tỏa
                    </span>
                  )}
                </div>
                <div className="text-sm font-bold text-white leading-snug break-words">
                  {n.label}
                </div>
                <div className="text-xs text-slate-300 break-words">{n.sublabel}</div>
              </div>
            ),
          },
          style: {
            background: styleCfg.bg,
            color: '#F8FAFC',
            border: `2px solid ${isFrozen ? '#10B981' : styleCfg.border}`,
            borderRadius: '14px',
            width: 265,
            padding: '6px',
            cursor: 'pointer',
            boxShadow: '0 10px 25px rgba(0,0,0,0.5)',
          },
        };
      });
  }, [frozenAccountIds, nodes, visibleNodeIds]);

  const flowEdges: Edge[] = useMemo(() => {
    return visibleEdges.map((e) => ({
      id: e.id,
      source: e.source,
      target: e.target,
      label: e.label,
      animated: e.animated,
      style: {
        stroke: e.isHighRisk ? '#F59E0B' : '#10B981',
        strokeWidth: 2.5,
      },
      labelStyle: {
        fill: '#F8FAFC',
        fontFamily: 'Be Vietnam Pro, sans-serif',
        fontSize: 12,
        fontWeight: 600,
      },
      labelBgPadding: [6, 4],
      labelBgBorderRadius: 6,
      labelBgStyle: {
        fill: '#0F172A',
        fillOpacity: 0.92,
      },
      markerEnd: {
        type: MarkerType.ArrowClosed,
        color: e.isHighRisk ? '#F59E0B' : '#10B981',
      },
    }));
  }, [visibleEdges]);

  const extractedTargetNumber = selectedNode?.sublabel.match(/\b(\d{8,16})\b/)?.[1] ?? selectedNode?.id;

  const canvasCard = (
    <section
      className={`bg-slate-900/95 border border-slate-800 rounded-2xl p-4 flex flex-col gap-2.5 shadow-lg ${
        isFullscreen ? 'fixed inset-4 z-50 border-slate-700 shadow-2xl' : ''
      }`}
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <GitBranch className="w-4 h-4 text-cyan-400" />
          <h2 className="text-sm font-bold text-white">
            Sơ đồ Truy vết Dòng tiền &amp; Thiết bị Liên kết ({alertId})
          </h2>
        </div>

        <div className="flex flex-wrap items-center gap-1.5 text-xs">
          {/* Layer Filters */}
          {(
            [
              { id: 'ALL', label: 'Tất cả' },
              { id: 'MONEY_ONLY', label: 'Dòng tiền' },
              { id: 'INFRA_ONLY', label: 'Thiết bị / API' },
            ] as const
          ).map((f) => (
            <button
              key={f.id}
              type="button"
              onClick={() => setLayerFilter(f.id)}
              className={`cursor-pointer px-2 py-0.5 rounded-lg text-[11px] font-bold border transition-colors ${
                layerFilter === f.id
                  ? 'bg-cyan-500/20 text-cyan-200 border-cyan-400'
                  : 'bg-slate-950 text-slate-300 border-slate-800 hover:text-white'
              }`}
            >
              {f.label}
            </button>
          ))}

          <button
            type="button"
            onClick={() => setIsFullscreen((v) => !v)}
            title={isFullscreen ? 'Thu nhỏ sơ đồ' : 'Phóng to Toàn màn hình'}
            className="cursor-pointer inline-flex items-center gap-1 px-2.5 py-0.5 rounded-lg text-[11px] font-bold bg-slate-800 hover:bg-slate-700 text-amber-300 border border-slate-700"
          >
            {isFullscreen ? (
              <>
                <Minimize2 className="w-3 h-3" />
                <span>Thu nhỏ</span>
              </>
            ) : (
              <>
                <Maximize2 className="w-3 h-3" />
                <span>Toàn màn hình</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Legend Bar */}
      <div className="flex flex-wrap items-center gap-3 text-[11px]">
        <span className="flex items-center gap-1 text-cyan-300">
          <User className="w-3 h-3" /> Khách hàng
        </span>
        <span className="flex items-center gap-1 text-red-300">
          <ShieldAlert className="w-3 h-3" /> Tài khoản nhận nghi vấn
        </span>
        <span className="flex items-center gap-1 text-amber-300">
          <Cpu className="w-3 h-3" /> Thiết bị / API liên kết
        </span>
      </div>

      <div
        className={`w-full rounded-xl border border-slate-800 bg-slate-950 overflow-hidden relative ${
          isFullscreen ? 'flex-1 min-h-[420px]' : 'h-[245px]'
        }`}
      >
        <ReactFlow
          nodes={flowNodes}
          edges={flowEdges}
          fitView
          fitViewOptions={{ padding: 0.22 }}
          onNodeClick={(_, node) => {
            const found = nodes.find((n) => n.id === node.id) ?? null;
            setSelectedNode(found);
            if (found?.evidenceId) {
              onSelectEvidenceId(found.evidenceId);
            }
          }}
          proOptions={{ hideAttribution: true }}
        >
          <Background color="#1E293B" gap={20} />
          <Controls showInteractive={false} />
        </ReactFlow>
      </div>

      {selectedNode ? (
        <div className="px-3 py-2 rounded-xl bg-slate-950 border border-amber-500/40 flex flex-wrap items-center justify-between gap-2 text-xs">
          <div className="min-w-0">
            <span className="text-amber-400 font-bold">{selectedNode.label}</span>{' '}
            <span className="text-slate-300">• {selectedNode.sublabel}</span>
          </div>
          <div className="flex flex-wrap items-center gap-1.5">
            {selectedNode.evidenceId && (
              <button
                type="button"
                onClick={() => onSelectEvidenceId(selectedNode.evidenceId!)}
                className="cursor-pointer inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 border border-amber-500/40 font-bold text-[11px]"
              >
                <ExternalLink className="w-3 h-3" />
                <span>Soi Bằng chứng {selectedNode.evidenceId}</span>
              </button>
            )}
            {onTestNodeInWallet &&
              (selectedNode.nodeKind === 'SUSPECT_MULE' ||
                selectedNode.nodeKind === 'TRUSTED_PARTNER') &&
              extractedTargetNumber && (
                <button
                  type="button"
                  onClick={() => onTestNodeInWallet(extractedTargetNumber)}
                  className="cursor-pointer inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 border border-emerald-500/40 font-bold text-[11px]"
                >
                  <Smartphone className="w-3 h-3" />
                  <span>Test STK {extractedTargetNumber} trên Ví</span>
                </button>
              )}
          </div>
        </div>
      ) : (
        <p className="text-[11px] text-slate-400">
          Mẹo: Bấm vào bất kỳ ô nào trên sơ đồ để soi bằng chứng gốc hoặc đưa STK sang Ví kiểm chứng chặn.
        </p>
      )}
    </section>
  );

  return (
    <>
      {isFullscreen && (
        <div
          onClick={() => setIsFullscreen(false)}
          className="fixed inset-0 z-40 bg-slate-950/85 backdrop-blur-sm"
        />
      )}
      {canvasCard}
    </>
  );
};
