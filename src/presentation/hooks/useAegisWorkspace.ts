'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  CASE_BUILDER_PRESETS,
  deriveCaseInputSpecFromAlert,
} from '@/domain/sandbox-synthesizer';
import type { MerchantBillVerificationResult } from '@/domain/merchant-verifier';
import type {
  ClawbackReceiptRecord,
  ConsumerTransferDecision,
  ForensicSuiteOutput,
  HitlFeedbackDecision,
  HitlFeedbackMemoryRecord,
  HitlFeedbackReasonCode,
  HitlFeedbackTargetScope,
  InvestigationReport,
  MerchantVisionVerificationBundle,
  OperatorRole,
  SessionDeltaSnapshot,
  SimoReceiptRecord,
  StandardCaseInputSpec,
  WorkspaceNotification,
} from '@/domain/types';
import type { MaterializedWorkspaceState } from '@/infrastructure/workspace-store';

const SESSION_ID_KEY = 'aegisops_session_id_v1';
const DELTA_STORAGE_KEY = 'aegisops_session_delta_v1';

export interface ChatMessageItem {
  id: string;
  role: 'analyst' | 'copilot';
  text: string;
  modelUsed?: string;
  citedIds?: string[];
}

export const useAegisWorkspace = () => {
  const [sessionId, setSessionId] = useState<string>('judge-default-session');
  const [workspaceState, setWorkspaceState] = useState<MaterializedWorkspaceState | null>(null);
  const [forensicsMap, setForensicsMap] = useState<Record<string, ForensicSuiteOutput>>({});
  const [selectedAlertId, setSelectedAlertId] = useState<string>('ALT-APP-003');
  const [isInvestigating, setIsInvestigating] = useState<boolean>(false);
  const [isApprovingPlaybook, setIsApprovingPlaybook] = useState<boolean>(false);
  const [isWalletOpen, setIsWalletOpen] = useState<boolean>(false);
  const [isSplitScreen, setIsSplitScreen] = useState<boolean>(false);
  const [isAutoDemoRunning, setIsAutoDemoRunning] = useState<boolean>(false);
  const [isSandboxOpen, setIsSandboxOpen] = useState<boolean>(false);
  const [sandboxInitialSpec, setSandboxInitialSpec] = useState<StandardCaseInputSpec | null>(null);
  const [highlightedEvidenceId, setHighlightedEvidenceId] = useState<string | null>(null);
  const [walletPrefillAccount, setWalletPrefillAccount] = useState<string>('1903999888777');
  const [walletPrefillAmount, setWalletPrefillAmount] = useState<number>(18_000_000);
  const [lastWalletDecision, setLastWalletDecision] = useState<ConsumerTransferDecision | null>(null);
  const [chatByAlertId, setChatByAlertId] = useState<Record<string, ChatMessageItem[]>>({});
  const [isAskingCopilot, setIsAskingCopilot] = useState<boolean>(false);
  const [errorBanner, setErrorBanner] = useState<string | null>(null);
  const [operatorRole, setOperatorRole] = useState<OperatorRole>('L2_CHECKER');
  const [notifications, setNotifications] = useState<WorkspaceNotification[]>([
    {
      id: 'NOTIF-INIT-1',
      titleVi: 'Hệ thống AegisOps đã sẵn sàng',
      detailVi: 'Đã nạp 4 kịch bản Fintech mô phỏng & sẵn sàng 5 công cụ định lượng cùng Trợ lý Gemini.',
      severity: 'INFO',
      timestamp: '2026-11-21T09:00:00+07:00',
      read: true,
    },
  ]);
  const [toasts, setToasts] = useState<WorkspaceNotification[]>([]);
  const [isImportingBatch, setIsImportingBatch] = useState<boolean>(false);
  const [isLiveFeedEnabled, setIsLiveFeedEnabled] = useState<boolean>(false);

  const pushNotification = useCallback(
    (item: Omit<WorkspaceNotification, 'id' | 'timestamp' | 'read'>) => {
      const notif: WorkspaceNotification = {
        ...item,
        id: `NTF-${Date.now()}-${Math.random().toString(36).slice(2, 5)}`,
        timestamp: new Date().toISOString(),
        read: false,
      };
      setNotifications((prev) => [notif, ...prev].slice(0, 25));
      setToasts((prev) => [notif, ...prev].slice(0, 3));
      setTimeout(() => {
        setToasts((prev) => prev.filter((t) => t.id !== notif.id));
      }, 4800);
    },
    []
  );

  const dismissToast = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const markAllNotificationsRead = useCallback(() => {
    setNotifications((prev) => prev.map((n) => ({ ...n, read: true })));
  }, []);

  const persistDelta = useCallback((delta: SessionDeltaSnapshot) => {
    try {
      localStorage.setItem(DELTA_STORAGE_KEY, JSON.stringify(delta));
    } catch {
      // Ignore storage quota errors
    }
  }, []);

  const readStoredDelta = useCallback((): Partial<SessionDeltaSnapshot> | null => {
    try {
      const raw = localStorage.getItem(DELTA_STORAGE_KEY);
      return raw ? (JSON.parse(raw) as Partial<SessionDeltaSnapshot>) : null;
    } catch {
      return null;
    }
  }, []);

  const refreshWorkspace = useCallback(
    async (sid: string, overrideDelta?: Partial<SessionDeltaSnapshot> | null) => {
      const deltaToSend = overrideDelta !== undefined ? overrideDelta : readStoredDelta();
      const res = await fetch('/api/workspace', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-workspace-session': sid },
        body: JSON.stringify({ clientDelta: deltaToSend }),
      });
      if (!res.ok) return;
      const data = (await res.json()) as {
        state: MaterializedWorkspaceState;
        forensicsByAlertId: Record<string, ForensicSuiteOutput>;
      };
      setWorkspaceState(data.state);
      setForensicsMap(data.forensicsByAlertId);
      persistDelta(data.state.delta);
    },
    [persistDelta, readStoredDelta]
  );

  const syncSignedSession = useCallback(async (sid: string, role: OperatorRole): Promise<string | null> => {
    try {
      const res = await fetch('/api/session', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-workspace-session': sid },
        body: JSON.stringify({ sessionId: sid, role }),
      });
      if (res.ok) {
        const payload = (await res.json().catch(() => ({}))) as { sessionId?: string };
        return payload.sessionId || sid;
      }
      if (res.status === 401 || res.status === 403) {
        const freshSid = `judge-${Math.random().toString(36).slice(2, 9)}-${Date.now().toString(36)}`;
        const retryRes = await fetch('/api/session', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'x-workspace-session': freshSid },
          body: JSON.stringify({ sessionId: freshSid, role }),
        });
        if (retryRes.ok) {
          localStorage.setItem(SESSION_ID_KEY, freshSid);
          setSessionId(freshSid);
          return freshSid;
        }
      }
      return null;
    } catch {
      return null;
    }
  }, []);

  const changeOperatorRole = useCallback(
    async (nextRole: OperatorRole) => {
      setErrorBanner(null);
      const res = await fetch('/api/session', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-workspace-session': sessionId },
        body: JSON.stringify({ sessionId, role: nextRole }),
      });
      if (!res.ok) {
        const errData = (await res.json().catch(() => ({}))) as { errorVi?: string };
        setErrorBanner(errData.errorVi || 'Không thể cập nhật phiên làm việc.');
        return false;
      }
      await res.arrayBuffer();
      setOperatorRole(nextRole);
      pushNotification({
        titleVi: `Đã chuyển vai trò phiên sang ${nextRole}`,
        detailVi:
          nextRole === 'L1_MAKER'
            ? 'Quyền L1 Maker: Chỉ được trình đề xuất Playbook, mọi lệnh phong tỏa/Clawback/SIMO bị chặn tại API (HTTP 403).'
            : nextRole === 'END_USER'
              ? 'Quyền End-User: Chỉ truy cập Ví MoMo & báo cáo nghi vấn, toàn bộ API nội bộ bị chặn (HTTP 403).'
              : 'Quyền Quản lý Rủi ro L2 (Checker): Được cấp chữ ký phiên toàn quyền phê duyệt.',
        severity: 'INFO',
      });
      return true;
    },
    [pushNotification, sessionId]
  );

  useEffect(() => {
    let sid = localStorage.getItem(SESSION_ID_KEY);
    if (!sid || sid === 'judge-default-session') {
      sid = `judge-${Math.random().toString(36).slice(2, 9)}-${Date.now().toString(36)}`;
      localStorage.setItem(SESSION_ID_KEY, sid);
    }
    setSessionId(sid);
    void syncSignedSession(sid, 'L2_CHECKER').then((activeSid) => {
      if (activeSid) {
        return refreshWorkspace(activeSid);
      }
    });
  }, [refreshWorkspace, syncSignedSession]);

  const selectedAlert =
    workspaceState?.alerts.find((a) => a.id === selectedAlertId) ??
    workspaceState?.alerts[0] ??
    null;

  const activeForensics = selectedAlert ? forensicsMap[selectedAlert.id] ?? null : null;
  const activeReport: InvestigationReport | null =
    (selectedAlert && workspaceState?.delta.reportsByAlertId[selectedAlert.id]) ?? null;

  const activeInputSpec: StandardCaseInputSpec | null = useMemo(() => {
    if (!workspaceState || !selectedAlert) return null;
    return deriveCaseInputSpecFromAlert({
      alert: selectedAlert,
      accounts: workspaceState.accounts,
      devices: workspaceState.devices,
      authLogs: workspaceState.authLogs,
      transactions: workspaceState.transactions,
      apiEvents: workspaceState.apiEvents,
      evidences: workspaceState.evidences,
      storedSpec: workspaceState.delta.customInputSpecsByAlertId?.[selectedAlert.id],
    });
  }, [selectedAlert, workspaceState]);

  const openCaseBuilder = useCallback((initialSpec?: StandardCaseInputSpec | null) => {
    setSandboxInitialSpec(initialSpec ?? null);
    setIsSandboxOpen(true);
  }, []);

  const handleSelectAlert = useCallback(
    (alertId: string) => {
      setSelectedAlertId(alertId);
      setHighlightedEvidenceId(null);
      setLastWalletDecision(null);
      const alert = workspaceState?.alerts.find((a) => a.id === alertId);
      if (alert) {
        const targetAcc = workspaceState?.accounts.find(
          (acc) => acc.id === alert.targetRecipientAccountId
        );
        if (targetAcc) {
          setWalletPrefillAccount(targetAcc.accountNumber);
        }
      }
    },
    [workspaceState]
  );

  const runInvestigation = useCallback(
    async (targetAlertId?: string) => {
      const alertId = targetAlertId || selectedAlert?.id || 'ALT-APP-003';
      setIsInvestigating(true);
      setErrorBanner(null);
      try {
        const res = await fetch('/api/investigate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'x-workspace-session': sessionId },
          body: JSON.stringify({ alertId, clientDelta: readStoredDelta() }),
        });
        const data = (await res.json()) as {
          report?: InvestigationReport;
          delta?: SessionDeltaSnapshot;
          errorVi?: string;
        };
        if (!res.ok || !data.delta) {
          setErrorBanner(data.errorVi || 'Không thể chạy điều tra AI.');
          return null;
        }
        persistDelta(data.delta);
        await refreshWorkspace(sessionId, data.delta);
        if (data.report) {
          pushNotification({
            titleVi: `AI hoàn tất điều tra ${alertId}`,
            detailVi: `Phân loại: ${data.report.classification} (Tin cậy ${data.report.confidenceScore}% • ${data.report.latencyMs}ms)`,
            severity:
              data.report.classification === 'FALSE_POSITIVE_SAFE' ? 'SUCCESS' : 'WARNING',
            alertId,
          });
        }
        return data.delta;
      } catch {
        setErrorBanner('Mất kết nối tạm thời khi gọi AI Investigation.');
        return null;
      } finally {
        setIsInvestigating(false);
      }
    },
    [persistDelta, pushNotification, readStoredDelta, refreshWorkspace, selectedAlert?.id, sessionId]
  );

  const approvePlaybook = useCallback(
    async (
      targetAlertId?: string,
      overrideDelta?: Partial<SessionDeltaSnapshot> | null,
      forceMode?: 'PROPOSE_L1' | 'APPROVE_L2'
    ) => {
      const alertId = targetAlertId || selectedAlert?.id;
      if (!alertId || isApprovingPlaybook) return null;
      const mode: 'PROPOSE_L1' | 'APPROVE_L2' =
        forceMode ?? (operatorRole === 'L1_MAKER' ? 'PROPOSE_L1' : 'APPROVE_L2');
      setIsApprovingPlaybook(true);
      setErrorBanner(null);
      try {
        const res = await fetch('/api/playbook', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'x-workspace-session': sessionId },
          body: JSON.stringify({
            alertId,
            mode,
            clientDelta: overrideDelta ?? readStoredDelta(),
          }),
        });
        const data = (await res.json()) as {
          delta?: SessionDeltaSnapshot;
          createdShieldRule?: { targetAccountNumber: string };
          newStatus?: string;
          proposedForL2?: boolean;
          errorVi?: string;
        };
        if (!res.ok || !data.delta) {
          setErrorBanner(data.errorVi || 'Lỗi khi duyệt Playbook.');
          return null;
        }
        if (data.createdShieldRule?.targetAccountNumber) {
          setWalletPrefillAccount(data.createdShieldRule.targetAccountNumber);
        }
        persistDelta(data.delta);
        await refreshWorkspace(sessionId, data.delta);
        if (data.proposedForL2) {
          pushNotification({
            titleVi: `L1 đã trình duyệt Playbook ${alertId}`,
            detailVi: 'Đã gửi hồ sơ sang hàng chờ Quản lý Rủi ro L2 (Checker) phê duyệt theo nguyên tắc 4-Eyes.',
            severity: 'INFO',
            alertId,
          });
        } else if (data.newStatus === 'DISMISSED_SAFE') {
          pushNotification({
            titleVi: `Đã xác nhận An toàn cho ${alertId}`,
            detailVi: 'Khách hàng được bảo vệ không bị khóa tài khoản oan.',
            severity: 'SUCCESS',
            alertId,
          });
        } else {
          pushNotification({
            titleVi: `Đã bật Lá chắn Cộng đồng (${alertId})`,
            detailVi: `Phong tỏa STK đích ${data.createdShieldRule?.targetAccountNumber ?? ''} & đồng bộ xuống Ví Mô phỏng.`,
            severity: 'CRITICAL',
            alertId,
          });
        }
        return data.delta;
      } finally {
        setIsApprovingPlaybook(false);
      }
    },
    [
      isApprovingPlaybook,
      operatorRole,
      persistDelta,
      pushNotification,
      readStoredDelta,
      refreshWorkspace,
      selectedAlert?.id,
      sessionId,
    ]
  );

  const simulateWalletTransfer = useCallback(
    async (
      params: {
        senderAccountId?: string;
        recipientAccount: string;
        amountVnd: number;
        message: string;
        idempotencyKey?: string;
      },
      overrideDelta?: Partial<SessionDeltaSnapshot> | null
    ) => {
      setErrorBanner(null);
      const res = await fetch('/api/wallet', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-workspace-session': sessionId },
        body: JSON.stringify({
          senderAccountId: params.senderAccountId ?? 'ACC-USR-103',
          senderName: 'Nguyễn Thị Thu Hà (Khách hàng Ví MoMo)',
          recipientAccountIdOrNumber: params.recipientAccount,
          amountVnd: Math.round(params.amountVnd),
          message: params.message,
          idempotencyKey: params.idempotencyKey,
          clientDelta: overrideDelta ?? readStoredDelta(),
        }),
      });
      const data = (await res.json()) as {
        decision?: ConsumerTransferDecision;
        delta?: SessionDeltaSnapshot;
        errorVi?: string;
      };
      if (!res.ok) {
        setErrorBanner(data.errorVi || 'Không thể thực hiện giao dịch Ví.');
        return null;
      }
      if (data.decision) {
        setLastWalletDecision(data.decision);
        if (data.decision.decision === 'BLOCKED_BY_SHIELD') {
          pushNotification({
            titleVi: `Ví MoMo vừa chặn đứng ${params.amountVnd.toLocaleString('vi-VN')} ₫`,
            detailVi: `Lá chắn ${data.decision.matchedRuleId ?? ''} đã ngăn chuyển tiền vào ${params.recipientAccount} trong ${data.decision.responseTimeMs}ms.`,
            severity: 'CRITICAL',
          });
        }
      }
      if (data.delta) {
        persistDelta(data.delta);
        await refreshWorkspace(sessionId, data.delta);
      }
      return data.decision ?? null;
    },
    [persistDelta, pushNotification, readStoredDelta, refreshWorkspace, sessionId]
  );

  const submitSandboxCase = useCallback(
    async (payload: {
      customTitle?: string;
      rawTranscript: string;
      imageDataUrl?: string;
      recipientAccountNumber?: string;
      recipientOwnerName?: string;
      amountVnd?: number;
      caseInputSpec?: Partial<StandardCaseInputSpec>;
    }) => {
      setIsInvestigating(true);
      setErrorBanner(null);
      try {
        const requestPayload = { ...payload, clientDelta: readStoredDelta() };
        const serializedBody = JSON.stringify(requestPayload);
        const bodyBytes = new TextEncoder().encode(serializedBody).byteLength;
        if (bodyBytes > 4 * 1024 * 1024) {
          setErrorBanner(
            'Tổng dung lượng dữ liệu gửi lên vượt quá giới hạn 4 MiB (4.194.304 bytes). Vui lòng chọn ảnh nhỏ hơn.'
          );
          return false;
        }
        const res = await fetch('/api/sandbox', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'x-workspace-session': sessionId },
          body: serializedBody,
        });
        const data = (await res.json().catch(() => ({}))) as {
          createdAlertId?: string;
          extractedRecipientAccountNumber?: string;
          delta?: SessionDeltaSnapshot;
          errorVi?: string;
        };
        if (res.status === 413) {
          setErrorBanner(
            data.errorVi ||
              'Tổng dung lượng dữ liệu tải lên vượt quá giới hạn 4 MiB (HTTP 413). Vui lòng chọn hoặc nén ảnh nhỏ hơn.'
          );
          return false;
        }
        if (!res.ok || !data.delta || !data.createdAlertId) {
          setErrorBanner(data.errorVi || 'Lỗi tạo hồ sơ kiểm thử.');
          return false;
        }
        persistDelta(data.delta);
        await refreshWorkspace(sessionId, data.delta);
        setSelectedAlertId(data.createdAlertId);
        if (data.extractedRecipientAccountNumber) {
          setWalletPrefillAccount(data.extractedRecipientAccountNumber);
        }
        if (payload.caseInputSpec?.amountVnd && payload.caseInputSpec.amountVnd > 0) {
          setWalletPrefillAmount(payload.caseInputSpec.amountVnd);
        }
        setIsSandboxOpen(false);
        return true;
      } finally {
        setIsInvestigating(false);
      }
    },
    [persistDelta, readStoredDelta, refreshWorkspace, sessionId]
  );

  // Two-Way Closed-Loop: End-user on Consumer Wallet reports suspicious transfer directly to AegisOps Queue
  const escalateFromConsumerWallet = useCallback(
    async (params: { recipientAccount: string; amountVnd: number; message: string }) => {
      return submitSandboxCase({
        customTitle: `[Báo động Khẩn từ Ví MoMo] Khách hàng nghi bị lừa chuyển ${params.amountVnd.toLocaleString('vi-VN')} ₫`,
        rawTranscript: `Khách hàng trên Ví MoMo bấm nút Cầu cứu Khẩn cấp khi đang chuẩn bị chuyển ${params.amountVnd.toLocaleString('vi-VN')} VNĐ vào STK ${params.recipientAccount} với nội dung: "${params.message}". Yêu cầu đội ngũ AegisOps điều tra và bật Lá chắn Cộng đồng ngay!`,
        recipientAccountNumber: params.recipientAccount,
        amountVnd: params.amountVnd,
      });
    },
    [submitSandboxCase]
  );

  // 1-Click Auto-Pilot Walkthrough for busy Judges (Upgrade #5)
  const runAutoPilotDemo = useCallback(async () => {
    if (isAutoDemoRunning) return;
    setIsAutoDemoRunning(true);
    try {
      setIsSplitScreen(true);
      setSelectedAlertId('ALT-APP-003');
      setWalletPrefillAccount('1903999888777');
      setHighlightedEvidenceId('EVD-103');

      const invDelta = await runInvestigation('ALT-APP-003');
      await new Promise((r) => setTimeout(r, 900));

      const playDelta = await approvePlaybook('ALT-APP-003', invDelta, 'APPROVE_L2');
      await new Promise((r) => setTimeout(r, 800));

      await simulateWalletTransfer(
        {
          recipientAccount: '1903999888777',
          amountVnd: 18_000_000,
          message: 'Chuyen tien xac minh tai san theo yeu cau cong an',
        },
        playDelta ?? invDelta
      );
    } finally {
      setIsAutoDemoRunning(false);
    }
  }, [approvePlaybook, isAutoDemoRunning, runInvestigation, simulateWalletTransfer]);

  const askCopilot = useCallback(
    async (question: string) => {
      if (!selectedAlert || !question.trim()) return;
      const alertId = selectedAlert.id;
      const userMsg: ChatMessageItem = {
        id: `usr-${Date.now()}`,
        role: 'analyst',
        text: question.trim(),
      };
      setChatByAlertId((prev) => ({
        ...prev,
        [alertId]: [...(prev[alertId] ?? []), userMsg],
      }));
      setIsAskingCopilot(true);
      try {
        const res = await fetch('/api/copilot', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'x-workspace-session': sessionId },
          body: JSON.stringify({
            alertId,
            question: question.trim(),
            clientDelta: readStoredDelta(),
          }),
        });
        const data = (await res.json()) as {
          answerVi?: string;
          modelUsed?: string;
          citedEvidenceIds?: string[];
        };
        const botMsg: ChatMessageItem = {
          id: `bot-${Date.now()}`,
          role: 'copilot',
          text: data.answerVi || 'Đã ghi nhận truy vấn.',
          modelUsed: data.modelUsed,
          citedIds: data.citedEvidenceIds,
        };
        setChatByAlertId((prev) => ({
          ...prev,
          [alertId]: [...(prev[alertId] ?? []), botMsg],
        }));
      } finally {
        setIsAskingCopilot(false);
      }
    },
    [readStoredDelta, selectedAlert, sessionId]
  );

  const resetDemoWorkspace = useCallback(async () => {
    localStorage.removeItem(DELTA_STORAGE_KEY);
    const res = await fetch('/api/workspace', {
      method: 'DELETE',
      headers: { 'x-workspace-session': sessionId },
    });
    if (res.ok) {
      const data = (await res.json()) as {
        state: MaterializedWorkspaceState;
        forensicsByAlertId: Record<string, ForensicSuiteOutput>;
      };
      setWorkspaceState(data.state);
      setForensicsMap(data.forensicsByAlertId);
      setSelectedAlertId('ALT-APP-003');
      setWalletPrefillAccount('1903999888777');
      setLastWalletDecision(null);
      setHighlightedEvidenceId(null);
      setChatByAlertId({});
      persistDelta(data.state.delta);
    }
  }, [persistDelta, sessionId]);

  const importBatchCasesFile = useCallback(
    async (rawContent: string, fileName: string) => {
      setIsImportingBatch(true);
      setErrorBanner(null);
      try {
        const res = await fetch('/api/batch-import', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'x-workspace-session': sessionId },
          body: JSON.stringify({
            rawContent,
            fileName,
            clientDelta: readStoredDelta(),
          }),
        });
        const data = (await res.json()) as {
          importedCount?: number;
          createdAlertIds?: string[];
          delta?: SessionDeltaSnapshot;
          errorVi?: string;
        };
        if (!res.ok || !data.delta) {
          setErrorBanner(data.errorVi || 'Không thể nhập dữ liệu từ file CSV/JSON.');
          return false;
        }
        persistDelta(data.delta);
        await refreshWorkspace(sessionId, data.delta);
        if (data.createdAlertIds?.[0]) {
          setSelectedAlertId(data.createdAlertIds[0]);
        }
        pushNotification({
          titleVi: `Đã nhập thành công ${data.importedCount ?? 0} hồ sơ từ ${fileName}`,
          detailVi: 'Toàn bộ lô dữ liệu đã được 5 công cụ định lượng chấm điểm & cập nhật lên Dashboard.',
          severity: 'SUCCESS',
          alertId: data.createdAlertIds?.[0],
        });
        return true;
      } catch {
        setErrorBanner('Lỗi đọc hoặc tải lên tệp dữ liệu hàng loạt.');
        return false;
      } finally {
        setIsImportingBatch(false);
      }
    },
    [persistDelta, pushNotification, readStoredDelta, refreshWorkspace, sessionId]
  );

  // Live Attack Feed Simulation (triggers realistic live events when enabled)
  useEffect(() => {
    if (!isLiveFeedEnabled) return;
    const timer = setInterval(() => {
      const presets = CASE_BUILDER_PRESETS;
      const sample = presets[Math.floor(Math.random() * presets.length)]!;
      pushNotification({
        titleVi: `Cảnh báo Live Feed: ${sample.spec.channel} • ${sample.spec.amountVnd.toLocaleString('vi-VN')} ₫`,
        detailVi: `${sample.spec.senderName} → ${sample.spec.recipientAccountNumber} (${sample.expectedRiskLabelVi})`,
        severity: sample.id === 'PRESET-SAFE' ? 'INFO' : 'WARNING',
      });
    }, 6500);
    return () => clearInterval(timer);
  }, [isLiveFeedEnabled, pushNotification]);

  const acknowledgeDeEscalationCancel = useCallback(
    async (params: { recipientAccount: string; amountVnd: number }) => {
      const res = await fetch('/api/wallet', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-workspace-session': sessionId },
        body: JSON.stringify({
          action: 'SELF_RESCUE_CANCEL',
          recipientAccountIdOrNumber: params.recipientAccount,
          amountVnd: params.amountVnd,
          clientDelta: readStoredDelta(),
        }),
      });
      const data = (await res.json()) as {
        delta?: SessionDeltaSnapshot;
        savedTotalVnd?: number;
      };
      if (data.delta) {
        persistDelta(data.delta);
        await refreshWorkspace(sessionId, data.delta);
        pushNotification({
          titleVi: `Khách hàng đã tỉnh táo HỦY giao dịch ${params.amountVnd.toLocaleString('vi-VN')} ₫`,
          detailVi: `Người dùng đã đọc Thẻ Gỡ bùa Tâm lý và hủy chuyển tới ${params.recipientAccount}. Tài sản được bảo vệ nguyên vẹn!`,
          severity: 'SUCCESS',
        });
        return true;
      }
      return false;
    },
    [persistDelta, pushNotification, readStoredDelta, refreshWorkspace, sessionId]
  );

  const toggleShieldRule = useCallback(
    async (ruleId: string) => {
      setErrorBanner(null);
      const res = await fetch('/api/playbook', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-workspace-session': sessionId },
        body: JSON.stringify({
          mode: 'TOGGLE_SHIELD',
          ruleId,
          clientDelta: readStoredDelta(),
        }),
      });
      const data = (await res.json()) as {
        delta?: SessionDeltaSnapshot;
        updatedRule?: { id: string; active: boolean; targetAccountNumber: string };
        errorVi?: string;
      };
      if (!res.ok) {
        setErrorBanner(data.errorVi || 'Không có quyền thay đổi quy tắc Lá chắn.');
        return false;
      }
      if (data.delta) {
        persistDelta(data.delta);
        await refreshWorkspace(sessionId, data.delta);
        if (data.updatedRule) {
          pushNotification({
            titleVi: `${data.updatedRule.active ? 'Đã bật lại' : 'Đã tạm dừng'} Lá chắn ${data.updatedRule.id}`,
            detailVi: `Quy tắc chặn STK ${data.updatedRule.targetAccountNumber} hiện đang ${data.updatedRule.active ? 'HOẠT ĐỘNG' : 'TẠM DỪNG'
              }. Hãy test ngay trên Ví MoMo!`,
            severity: data.updatedRule.active ? 'SUCCESS' : 'WARNING',
          });
        }
        return true;
      }
      return false;
    },
    [persistDelta, pushNotification, readStoredDelta, refreshWorkspace, sessionId]
  );

  const addCustomShieldRule = useCallback(
    async (params: {
      targetAccountNumber: string;
      targetOwnerName?: string;
      reasonVi?: string;
    }) => {
      const res = await fetch('/api/playbook', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-workspace-session': sessionId },
        body: JSON.stringify({
          mode: 'ADD_CUSTOM_SHIELD',
          targetAccountNumber: params.targetAccountNumber,
          targetOwnerName: params.targetOwnerName,
          reasonVi: params.reasonVi,
          clientDelta: readStoredDelta(),
        }),
      });
      const data = (await res.json()) as {
        delta?: SessionDeltaSnapshot;
        createdShieldRule?: { id: string; targetAccountNumber: string };
        errorVi?: string;
      };
      if (!res.ok || !data.delta) {
        setErrorBanner(data.errorVi || 'Không thể thêm quy tắc chặn.');
        return false;
      }
      persistDelta(data.delta);
      await refreshWorkspace(sessionId, data.delta);
      setWalletPrefillAccount(params.targetAccountNumber.trim());
      pushNotification({
        titleVi: `Đã thêm quy tắc chặn STK ${params.targetAccountNumber}`,
        detailVi: `Lá chắn ${data.createdShieldRule?.id ?? ''} đã đồng bộ xuống Ví MoMo (<5ms).`,
        severity: 'CRITICAL',
      });
      return true;
    },
    [persistDelta, pushNotification, readStoredDelta, refreshWorkspace, sessionId]
  );

  const runBatchTriageCluster = useCallback(async () => {
    setErrorBanner(null);
    const res = await fetch('/api/playbook', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-workspace-session': sessionId },
      body: JSON.stringify({
        mode: 'BATCH_TRIAGE',
        clientDelta: readStoredDelta(),
      }),
    });
    const data = (await res.json()) as {
      clusteredMitigatedIds?: string[];
      autoClearedSafeIds?: string[];
      delta?: SessionDeltaSnapshot;
      errorVi?: string;
    };
    if (!res.ok || !data.delta) {
      setErrorBanner(data.errorVi || 'Lỗi khi xử lý gom nhóm chiến dịch.');
      return false;
    }
    persistDelta(data.delta);
    await refreshWorkspace(sessionId, data.delta);
    pushNotification({
      titleVi: 'Hoàn tất Xử lý Gom nhóm 1-Chạm (Batch Triage)',
      detailVi: `Đã khóa cụm liên kết (${data.clusteredMitigatedIds?.join(', ') || 'Đã khóa sẵn'}) & Auto-Clear ca an toàn (${data.autoClearedSafeIds?.join(', ') || '0 ca'}).`,
      severity: 'SUCCESS',
    });
    return true;
  }, [persistDelta, pushNotification, readStoredDelta, refreshWorkspace, sessionId]);

  const submitAnalystOverride = useCallback(
    async (params: {
      alertId: string;
      targetVerdict: 'OVERRIDE_SAFE' | 'FORCE_BLOCK';
      reasonVi: string;
    }) => {
      const res = await fetch('/api/playbook', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-workspace-session': sessionId },
        body: JSON.stringify({
          mode: 'ANALYST_OVERRIDE',
          alertId: params.alertId,
          targetVerdict: params.targetVerdict,
          reasonVi: params.reasonVi,
          clientDelta: readStoredDelta(),
        }),
      });
      const data = (await res.json()) as {
        delta?: SessionDeltaSnapshot;
        errorVi?: string;
      };
      if (!res.ok || !data.delta) {
        setErrorBanner(data.errorVi || 'Không thể ghi nhận quyết định ghi đè.');
        return false;
      }
      persistDelta(data.delta);
      await refreshWorkspace(sessionId, data.delta);
      pushNotification({
        titleVi: `Chuyên viên đã Ghi đè HITL vụ ${params.alertId}`,
        detailVi:
          params.targetVerdict === 'OVERRIDE_SAFE'
            ? 'Đã đảo quyết định sang An toàn (Gỡ khóa oan) & lưu tín hiệu huấn luyện AI.'
            : 'Đã cưỡng chế Phong tỏa & Bật Lá chắn bảo vệ.',
        severity: params.targetVerdict === 'OVERRIDE_SAFE' ? 'SUCCESS' : 'CRITICAL',
        alertId: params.alertId,
      });
      return true;
    },
    [persistDelta, pushNotification, readStoredDelta, refreshWorkspace, sessionId]
  );

  const pushDossierToSimo = useCallback(
    async (alertId: string) => {
      const res = await fetch('/api/playbook', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-workspace-session': sessionId },
        body: JSON.stringify({
          mode: 'PUSH_SIMO',
          alertId,
          clientDelta: readStoredDelta(),
        }),
      });
      const data = (await res.json()) as {
        receipt?: SimoReceiptRecord;
        delta?: SessionDeltaSnapshot;
        errorVi?: string;
      };
      if (!res.ok || !data.delta) {
        setErrorBanner(data.errorVi || 'Không thể đồng bộ lên Cổng SIMO NHNN.');
        return null;
      }
      persistDelta(data.delta);
      await refreshWorkspace(sessionId, data.delta);
      pushNotification({
        titleVi: `Đã tạo biên nhận SIMO mô phỏng (${alertId})`,
        detailVi: `Mã biên nhận cục bộ: ${data.receipt?.receiptId ?? ''} (giả danh PII HMAC-SHA-256 — Luật 91/2025/QH15 & NĐ 356/2025/NĐ-CP; chưa kết nối SIMO thực).`,
        severity: 'SUCCESS',
        alertId,
      });
      return data.receipt ?? null;
    },
    [persistDelta, pushNotification, readStoredDelta, refreshWorkspace, sessionId]
  );

  const executeClawbackRefund = useCallback(
    async (alertId: string) => {
      setErrorBanner(null);
      const res = await fetch('/api/playbook', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-workspace-session': sessionId },
        body: JSON.stringify({
          mode: 'CLAWBACK_REFUND',
          alertId,
          clientDelta: readStoredDelta(),
        }),
      });
      const data = (await res.json()) as {
        clawbackReceipt?: ClawbackReceiptRecord;
        delta?: SessionDeltaSnapshot;
        errorVi?: string;
      };
      if (!res.ok || !data.delta) {
        setErrorBanner(data.errorVi || 'Không thể thu hồi và hoàn trả dòng tiền.');
        return null;
      }
      persistDelta(data.delta);
      await refreshWorkspace(sessionId, data.delta);
      const status = data.clawbackReceipt?.recoveryStatus;
      pushNotification({
        titleVi:
          status === 'PARTIALLY_RECOVERED'
            ? `Thu hồi MỘT PHẦN cho Nạn nhân (${alertId})`
            : status === 'FAILED'
              ? `Thu hồi thất bại — TK Mule hết số dư (${alertId})`
              : `Đã Thu hồi & Hoàn tiền cho Nạn nhân (${alertId})`,
        detailVi: `Hoàn trả ${(data.clawbackReceipt?.recoveredAmountVnd ?? 0).toLocaleString('vi-VN')} ₫ về Ví "${data.clawbackReceipt?.victimOwnerName ?? ''}" (${data.clawbackReceipt?.reversalTxId ?? data.clawbackReceipt?.clawbackId ?? ''}).`,
        severity: status === 'FAILED' ? 'WARNING' : 'SUCCESS',
        alertId,
      });
      return data.clawbackReceipt ?? null;
    },
    [persistDelta, pushNotification, readStoredDelta, refreshWorkspace, sessionId]
  );

  const verifyMerchantManualReceipt = useCallback(
    async (params: {
      claimedTxId: string;
      claimedAmountVnd: number;
      merchantAccountIdOrNumber?: string;
    }): Promise<{ verification?: MerchantBillVerificationResult; errorVi?: string }> => {
      setErrorBanner(null);
      try {
        const res = await fetch('/api/merchant/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'x-workspace-session': sessionId },
          body: JSON.stringify({
            claimedTxId: params.claimedTxId,
            claimedAmountVnd: Math.max(0, Math.round(params.claimedAmountVnd || 0)),
            merchantAccountIdOrNumber: params.merchantAccountIdOrNumber,
            clientDelta: readStoredDelta(),
          }),
        });
        const data = (await res.json()) as {
          verification?: MerchantBillVerificationResult;
          delta?: SessionDeltaSnapshot;
          errorVi?: string;
        };
        if (data.delta) {
          persistDelta(data.delta);
          setWorkspaceState((prev) => (prev ? { ...prev, delta: data.delta! } : prev));
        }
        if (!res.ok || !data.verification) {
          return { errorVi: data.errorVi || 'Không thể đối soát hóa đơn Tiểu thương trên máy chủ.' };
        }
        return { verification: data.verification };
      } catch {
        return { errorVi: 'Mất kết nối tới máy chủ đối soát Tiểu thương (/api/merchant/verify).' };
      }
    },
    [persistDelta, readStoredDelta, sessionId]
  );

  const verifyMerchantVisionReceipt = useCallback(
    async (params: {
      imageDataUrl: string;
      merchantAccountIdOrNumber?: string;
    }): Promise<{ verification?: MerchantVisionVerificationBundle; errorVi?: string }> => {
      setErrorBanner(null);
      try {
        const requestPayload = {
          imageDataUrl: params.imageDataUrl,
          merchantAccountIdOrNumber: params.merchantAccountIdOrNumber,
          clientDelta: readStoredDelta(),
        };
        const serializedBody = JSON.stringify(requestPayload);
        const bodyBytes = new TextEncoder().encode(serializedBody).byteLength;
        if (bodyBytes > 4 * 1024 * 1024) {
          return {
            errorVi:
              'Tổng dung lượng dữ liệu gửi lên vượt quá giới hạn 4 MiB (4.194.304 bytes). Vui lòng chọn ảnh nhẹ hơn.',
          };
        }
        const res = await fetch('/api/merchant/vision', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'x-workspace-session': sessionId },
          body: serializedBody,
        });
        const data = (await res.json().catch(() => ({}))) as {
          verification?: MerchantVisionVerificationBundle;
          delta?: SessionDeltaSnapshot;
          errorVi?: string;
        };
        if (data.delta) {
          persistDelta(data.delta);
          await refreshWorkspace(sessionId, data.delta);
        }
        if (res.status === 413) {
          return {
            verification: data.verification,
            errorVi:
              data.errorVi ||
              'Ảnh hoặc dữ liệu gửi lên vượt quá giới hạn 4 MiB (HTTP 413). Vui lòng nén hoặc chọn ảnh nhỏ hơn.',
          };
        }
        if (!res.ok && !data.verification) {
          return { errorVi: data.errorVi || 'Lỗi kiểm tra ảnh Bill trên máy chủ.' };
        }
        return { verification: data.verification, errorVi: data.errorVi };
      } catch {
        return { errorVi: 'Mất kết nối khi gửi ảnh Bill tới Gemini Vision.' };
      }
    },
    [persistDelta, readStoredDelta, refreshWorkspace, sessionId]
  );

  const createHitlFeedback = useCallback(
    async (params: {
      alertId: string;
      feedbackDecision: HitlFeedbackDecision;
      targetScope?: HitlFeedbackTargetScope;
      reasonCode?: HitlFeedbackReasonCode;
      analystRationale: string;
      ttlHours?: number;
    }): Promise<HitlFeedbackMemoryRecord | null> => {
      setErrorBanner(null);
      const res = await fetch('/api/feedback', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-workspace-session': sessionId },
        body: JSON.stringify({
          action: 'CREATE',
          alertId: params.alertId,
          feedbackDecision: params.feedbackDecision,
          targetScope: params.targetScope ?? 'RECIPIENT_PATTERN',
          reasonCode: params.reasonCode,
          analystRationale: params.analystRationale,
          ttlHours: params.ttlHours ?? 24,
          clientDelta: readStoredDelta(),
        }),
      });
      const data = (await res.json()) as {
        feedbackRecord?: HitlFeedbackMemoryRecord;
        delta?: SessionDeltaSnapshot;
        errorVi?: string;
      };
      if (!res.ok || !data.delta) {
        setErrorBanner(data.errorVi || 'Không thể lưu phản hồi Adaptive HITL.');
        return null;
      }
      persistDelta(data.delta);
      await refreshWorkspace(sessionId, data.delta);
      pushNotification({
        titleVi:
          data.feedbackRecord?.status === 'APPROVED_ACTIVE'
            ? `Đã kích hoạt Bộ nhớ HITL (${data.feedbackRecord.feedbackId})`
            : `L1 đã đề xuất Bộ nhớ HITL (${data.feedbackRecord?.feedbackId ?? ''})`,
        detailVi: `Phạm vi ${data.feedbackRecord?.targetScope} • Điều chỉnh ${data.feedbackRecord?.riskAdjustment}đ • Chờ L2 hoặc đang có hiệu lực.`,
        severity: data.feedbackRecord?.feedbackDecision === 'FORCE_BLOCK' ? 'WARNING' : 'INFO',
        alertId: params.alertId,
      });
      return data.feedbackRecord ?? null;
    },
    [persistDelta, pushNotification, readStoredDelta, refreshWorkspace, sessionId]
  );

  const moderateHitlFeedback = useCallback(
    async (params: {
      feedbackId: string;
      action: 'APPROVE' | 'REJECT' | 'REVOKE';
      rejectReasonVi?: string;
    }): Promise<boolean> => {
      setErrorBanner(null);
      const res = await fetch('/api/feedback', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-workspace-session': sessionId },
        body: JSON.stringify({
          action: params.action,
          feedbackId: params.feedbackId,
          rejectReasonVi: params.rejectReasonVi,
          clientDelta: readStoredDelta(),
        }),
      });
      const data = (await res.json()) as {
        feedbackRecord?: HitlFeedbackMemoryRecord;
        delta?: SessionDeltaSnapshot;
        errorVi?: string;
      };
      if (!res.ok || !data.delta) {
        setErrorBanner(data.errorVi || 'Không thể cập nhật trạng thái Bộ nhớ HITL.');
        return false;
      }
      persistDelta(data.delta);
      await refreshWorkspace(sessionId, data.delta);
      pushNotification({
        titleVi: `HITL ${params.feedbackId} → ${data.feedbackRecord?.status}`,
        detailVi: `Quản lý L2 đã ${params.action} phản hồi Adaptive Memory.`,
        severity: params.action === 'REVOKE' || params.action === 'REJECT' ? 'INFO' : 'SUCCESS',
      });
      return true;
    },
    [persistDelta, pushNotification, readStoredDelta, refreshWorkspace, sessionId]
  );

  const currentGuidedStep: 1 | 2 | 3 = !activeReport
    ? 1
    : selectedAlert?.status === 'MITIGATED' || selectedAlert?.status === 'DISMISSED_SAFE'
      ? 3
      : 2;

  return {
    sessionId,
    workspaceState,
    forensicsMap,
    selectedAlert,
    activeForensics,
    activeReport,
    activeInputSpec,
    isInvestigating,
    isApprovingPlaybook,
    isImportingBatch,
    isWalletOpen,
    setIsWalletOpen,
    isSplitScreen,
    setIsSplitScreen,
    isAutoDemoRunning,
    runAutoPilotDemo,
    isSandboxOpen,
    setIsSandboxOpen,
    sandboxInitialSpec,
    openCaseBuilder,
    highlightedEvidenceId,
    setHighlightedEvidenceId,
    walletPrefillAccount,
    setWalletPrefillAccount,
    walletPrefillAmount,
    setWalletPrefillAmount,
    lastWalletDecision,
    chatMessages: selectedAlert ? chatByAlertId[selectedAlert.id] ?? [] : [],
    isAskingCopilot,
    errorBanner,
    currentGuidedStep,
    operatorRole,
    setOperatorRole: changeOperatorRole,
    notifications,
    toasts,
    dismissToast,
    markAllNotificationsRead,
    isLiveFeedEnabled,
    setIsLiveFeedEnabled,
    handleSelectAlert,
    runInvestigation,
    approvePlaybook,
    simulateWalletTransfer,
    acknowledgeDeEscalationCancel,
    toggleShieldRule,
    addCustomShieldRule,
    runBatchTriageCluster,
    submitAnalystOverride,
    pushDossierToSimo,
    executeClawbackRefund,
    verifyMerchantManualReceipt,
    verifyMerchantVisionReceipt,
    createHitlFeedback,
    moderateHitlFeedback,
    submitSandboxCase,
    importBatchCasesFile,
    escalateFromConsumerWallet,
    askCopilot,
    resetDemoWorkspace,
  };
};
