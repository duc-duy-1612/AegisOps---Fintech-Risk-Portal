'use client';

import { useEffect, useMemo, useState } from 'react';
import { AlertCircle } from 'lucide-react';
import { deriveCaseInputSpecFromAlert } from '@/domain/sandbox-synthesizer';
import { useAegisWorkspace } from '@/presentation/hooks/useAegisWorkspace';
import {
  AppShellSidebar,
  type WorkspaceViewId,
} from '@/presentation/components/AppShellSidebar';
import {
  WorkspaceCommandHeader,
  type CaseTagFilterId,
  type TagFilterOption,
} from '@/presentation/components/WorkspaceCommandHeader';
import { OverviewDashboardView } from '@/presentation/components/OverviewDashboardView';
import { AlertTriageQueue } from '@/presentation/components/AlertTriageQueue';
import { MoneyFlowGraphCanvas } from '@/presentation/components/MoneyFlowGraphCanvas';
import { EvidenceTelemetryTabs } from '@/presentation/components/EvidenceTelemetryTabs';
import { AiCopilotInvestigationPanel } from '@/presentation/components/AiCopilotInvestigationPanel';
import { ConsumerWalletSimulator } from '@/presentation/components/ConsumerWalletSimulator';
import { LiveSandboxModal } from '@/presentation/components/LiveSandboxModal';
import { WalletShieldWorkspaceView } from '@/presentation/components/WalletShieldWorkspaceView';
import { ComplianceAuditWorkspaceView } from '@/presentation/components/ComplianceAuditWorkspaceView';
import { ToastNotificationStack } from '@/presentation/components/ToastNotificationStack';
import { CommandPaletteModal } from '@/presentation/components/CommandPaletteModal';

export default function AegisOpsHomePage() {
  const {
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
    lastWalletDecision,
    chatMessages,
    isAskingCopilot,
    errorBanner,
    currentGuidedStep,
    operatorRole,
    setOperatorRole,
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
  } = useAegisWorkspace();

  const [activeView, setActiveView] = useState<WorkspaceViewId>('DASHBOARD');
  const [sidebarCollapsed, setSidebarCollapsed] = useState<boolean>(false);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedTagFilter, setSelectedTagFilter] = useState<CaseTagFilterId>('ALL');
  const [showPendingOnly, setShowPendingOnly] = useState<boolean>(false);
  const [isCommandPaletteOpen, setIsCommandPaletteOpen] = useState<boolean>(false);

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setIsCommandPaletteOpen((v) => !v);
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, []);

  const allAlerts = useMemo(() => workspaceState?.alerts ?? [], [workspaceState]);

  const tagOptions: TagFilterOption[] = useMemo(() => {
    const countPending = allAlerts.filter(
      (a) => a.status === 'OPEN' || a.status === 'INVESTIGATING'
    ).length;
    const countResolved = allAlerts.filter(
      (a) => a.status === 'MITIGATED' || a.status === 'DISMISSED_SAFE'
    ).length;

    return [
      {
        id: 'ALL',
        labelVi: 'Tất cả',
        count: allAlerts.length,
        toneClass: 'bg-slate-950 text-slate-200 border-slate-700',
      },
      {
        id: 'MULTIMODAL_APP_FRAUD',
        labelVi: 'Chống lừa đảo',
        count: allAlerts.filter((a) => a.scenarioCode === 'MULTIMODAL_APP_FRAUD').length,
        toneClass: 'bg-amber-500/10 text-amber-300 border-amber-500/30',
      },
      {
        id: 'CYBER_ATO_MULE',
        labelVi: 'Chiếm đoạt ATO',
        count: allAlerts.filter((a) => a.scenarioCode === 'CYBER_ATO_MULE').length,
        toneClass: 'bg-red-500/10 text-red-300 border-red-500/30',
      },
      {
        id: 'BUSINESS_LOGIC_RACE',
        labelVi: 'Lỗi API Logic',
        count: allAlerts.filter((a) => a.scenarioCode === 'BUSINESS_LOGIC_RACE').length,
        toneClass: 'bg-violet-500/10 text-violet-300 border-violet-500/30',
      },
      {
        id: 'SMART_FALSE_POSITIVE',
        labelVi: 'Tránh khóa oan',
        count: allAlerts.filter((a) => a.scenarioCode === 'SMART_FALSE_POSITIVE').length,
        toneClass: 'bg-cyan-500/10 text-cyan-300 border-cyan-500/30',
      },
      {
        id: 'CUSTOM_SANDBOX',
        labelVi: 'Tự tạo Sandbox',
        count: allAlerts.filter((a) => a.scenarioCode === 'CUSTOM_SANDBOX').length,
        toneClass: 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30',
      },
      {
        id: 'STATUS_PENDING',
        labelVi: 'Chờ duyệt',
        count: countPending,
        toneClass: 'bg-slate-950 text-amber-200 border-slate-700',
      },
      {
        id: 'STATUS_RESOLVED',
        labelVi: 'Đã xử lý',
        count: countResolved,
        toneClass: 'bg-slate-950 text-emerald-300 border-slate-700',
      },
    ];
  }, [allAlerts]);

  const filteredAlerts = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return allAlerts.filter((alert) => {
      if (showPendingOnly && (alert.status === 'MITIGATED' || alert.status === 'DISMISSED_SAFE')) {
        return false;
      }
      if (selectedTagFilter === 'STATUS_PENDING') {
        if (alert.status !== 'OPEN' && alert.status !== 'INVESTIGATING') return false;
      } else if (selectedTagFilter === 'STATUS_RESOLVED') {
        if (alert.status !== 'MITIGATED' && alert.status !== 'DISMISSED_SAFE') return false;
      } else if (selectedTagFilter !== 'ALL' && alert.scenarioCode !== selectedTagFilter) {
        return false;
      }
      if (!q) return true;
      const haystack =
        `${alert.id} ${alert.title} ${alert.subtitle} ${alert.targetRecipientAccountId} ${alert.primaryAccountId}`.toLowerCase();
      return haystack.includes(q);
    });
  }, [allAlerts, searchQuery, selectedTagFilter, showPendingOnly]);

  if (!workspaceState || !selectedAlert || !activeForensics) {
    return (
      <main className="min-h-screen bg-aegis-bg text-aegis-text flex items-center justify-center p-6">
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 max-w-md w-full space-y-3">
          <div className="h-5 w-48 bg-slate-800 rounded animate-pulse" />
          <div className="h-3 w-full bg-slate-800/70 rounded animate-pulse" />
          <div className="h-24 w-full bg-slate-800/50 rounded-xl animate-pulse" />
        </div>
      </main>
    );
  }

  const mitigatedCount = workspaceState.alerts.filter((a) => a.status === 'MITIGATED').length;
  const pendingCount = workspaceState.alerts.filter(
    (a) => a.status === 'OPEN' || a.status === 'INVESTIGATING'
  ).length;
  const falsePositivesSaved = workspaceState.alerts.filter(
    (a) => a.status === 'DISMISSED_SAFE'
  ).length;

  const handleOpenAlertInvestigation = (alertId: string) => {
    handleSelectAlert(alertId);
    setActiveView('INVESTIGATION');
  };

  const handleEditAlertSpec = (alertId: string) => {
    const targetAlert = workspaceState.alerts.find((a) => a.id === alertId);
    if (!targetAlert) return;
    handleSelectAlert(alertId);
    const derivedSpec = deriveCaseInputSpecFromAlert({
      alert: targetAlert,
      accounts: workspaceState.accounts,
      devices: workspaceState.devices,
      authLogs: workspaceState.authLogs,
      transactions: workspaceState.transactions,
      apiEvents: workspaceState.apiEvents,
      evidences: workspaceState.evidences,
      storedSpec: workspaceState.delta.customInputSpecsByAlertId?.[targetAlert.id],
    });
    openCaseBuilder(derivedSpec);
  };

  const handleRunAutoPilot = () => {
    setActiveView('INVESTIGATION');
    void runAutoPilotDemo();
  };

  const handleSubmitFormAndInspect: typeof submitSandboxCase = async (payload) => {
    const ok = await submitSandboxCase(payload);
    if (ok) {
      setActiveView('INVESTIGATION');
    }
    return ok;
  };

  return (
    <div className="min-h-screen bg-aegis-bg text-aegis-text flex">
      {/* Left Vertical Collapsible Navigation Sidebar */}
      <div className="hidden md:flex">
        <AppShellSidebar
          activeView={activeView}
          collapsed={sidebarCollapsed}
          operatorRole={operatorRole}
          alertCount={workspaceState.alerts.length}
          pendingCount={pendingCount}
          activeShieldCount={workspaceState.delta.activeShieldRules.length}
          auditCount={workspaceState.delta.auditLogs.length}
          isSplitScreen={isSplitScreen}
          showPendingOnly={showPendingOnly}
          isLiveFeedEnabled={isLiveFeedEnabled}
          isAutoDemoRunning={isAutoDemoRunning}
          sessionId={sessionId}
          onSelectView={(view) => setActiveView(view)}
          onChangeRole={(role) => {
            void setOperatorRole(role).then((ok) => {
              if (!ok) return;
              if (role === 'END_USER') {
                setActiveView('WALLET_SHIELD');
              } else if (activeView === 'WALLET_SHIELD') {
                setActiveView('INVESTIGATION');
              }
            });
          }}
          onToggleCollapse={() => setSidebarCollapsed((c) => !c)}
          onToggleSplitScreen={() => {
            setIsSplitScreen((prev) => !prev);
            setActiveView('INVESTIGATION');
          }}
          onTogglePendingOnly={() => setShowPendingOnly((p) => !p)}
          onToggleLiveFeed={() => setIsLiveFeedEnabled((v) => !v)}
          onRunAutoDemo={handleRunAutoPilot}
          onResetDemo={resetDemoWorkspace}
        />
      </div>

      {/* Main Content Area: Top Horizontal Toolbar + Active Workspace View */}
      <div className="flex-1 min-w-0 flex flex-col">
        <WorkspaceCommandHeader
          activeView={activeView}
          operatorRole={operatorRole}
          searchQuery={searchQuery}
          selectedTagFilter={selectedTagFilter}
          tagOptions={tagOptions}
          notifications={notifications}
          currentGuidedStep={currentGuidedStep}
          walletPrefillAccount={walletPrefillAccount}
          activeShieldCount={workspaceState.delta.activeShieldRules.length}
          isAutoDemoRunning={isAutoDemoRunning}
          isInvestigating={isInvestigating}
          isApprovingPlaybook={isApprovingPlaybook}
          onSearchChange={setSearchQuery}
          onSelectTagFilter={(tag) => {
            setSelectedTagFilter(tag);
            if (activeView === 'CASE_BUILDER') {
              setActiveView('DASHBOARD');
            }
          }}
          onSelectView={(view) => setActiveView(view)}
          onOpenWalletModal={() => setIsWalletOpen(true)}
          onRunAutoDemo={handleRunAutoPilot}
          onRunInvestigation={() => void runInvestigation()}
          onApprovePlaybook={() => void approvePlaybook()}
          onMarkAllRead={markAllNotificationsRead}
          onOpenCommandPalette={() => setIsCommandPaletteOpen(true)}
        />

        {/* Mobile Compact Menu Switcher */}
        <div className="flex md:hidden items-center gap-1.5 px-3 py-2 bg-slate-950 border-b border-slate-800 overflow-x-auto">
          {(
            [
              { id: 'DASHBOARD', label: 'Dashboard' },
              { id: 'INVESTIGATION', label: 'Điều tra' },
              { id: 'CASE_BUILDER', label: 'Nhập Hồ sơ' },
              { id: 'WALLET_SHIELD', label: 'Ví & Lá chắn' },
              { id: 'COMPLIANCE_AUDIT', label: 'Pháp lý & Log' },
            ] as const
          ).map((m) => (
            <button
              key={m.id}
              type="button"
              onClick={() => setActiveView(m.id)}
              className={`shrink-0 px-3 py-1 rounded-lg text-xs font-bold ${
                activeView === m.id
                  ? 'bg-amber-500 text-slate-950'
                  : 'bg-slate-900 text-slate-300 border border-slate-800'
              }`}
            >
              {m.label}
            </button>
          ))}
        </div>

        {errorBanner && (
          <div className="px-4 pt-2.5">
            <div className="px-3.5 py-2 rounded-lg bg-red-500/20 border border-red-500/40 text-red-200 text-xs flex items-center gap-2">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{errorBanner}</span>
            </div>
          </div>
        )}

        {/* Active View Body */}
        <main className="p-3.5 flex-1 flex flex-col gap-3 max-w-[1680px] w-full mx-auto">
          {activeView === 'DASHBOARD' && (
            <OverviewDashboardView
              alerts={filteredAlerts}
              allAlertsCount={workspaceState.alerts.length}
              accounts={workspaceState.accounts}
              forensicsMap={forensicsMap}
              activeShieldRules={workspaceState.delta.activeShieldRules}
              pendingL2ApprovalAlertIds={workspaceState.delta.pendingL2ApprovalAlertIds}
              auditLogs={workspaceState.delta.auditLogs}
              clawbackReceipts={workspaceState.delta.clawbackReceipts ?? []}
              transactions={workspaceState.transactions}
              reportsByAlertId={workspaceState.delta.reportsByAlertId}
              falsePositivesSaved={falsePositivesSaved}
              mitigatedCount={mitigatedCount}
              selfRescuedAmountVnd={workspaceState.delta.selfRescuedAmountVnd ?? 0}
              isImportingBatch={isImportingBatch}
              isLiveFeedEnabled={isLiveFeedEnabled}
              onOpenAlertInvestigation={handleOpenAlertInvestigation}
              onEditAlertSpec={handleEditAlertSpec}
              onNavigateView={(view) => setActiveView(view)}
              onRunAutoDemo={handleRunAutoPilot}
              onImportBatchFile={importBatchCasesFile}
              onToggleLiveFeed={() => setIsLiveFeedEnabled((v) => !v)}
            />
          )}

          {activeView === 'INVESTIGATION' && (
            <>
              {isSplitScreen && (
                <AlertTriageQueue
                  alerts={filteredAlerts.length > 0 ? filteredAlerts : workspaceState.alerts}
                  forensicsMap={forensicsMap}
                  selectedAlertId={selectedAlert.id}
                  compactHorizontal={true}
                  canExecuteBatchTriage={operatorRole === 'L2_CHECKER'}
                  onSelectAlert={handleSelectAlert}
                  onOpenSandbox={() => setActiveView('CASE_BUILDER')}
                  onExecuteBatchTriage={runBatchTriageCluster}
                />
              )}

              <div
                className={`grid grid-cols-1 lg:grid-cols-12 gap-3.5 ${
                  isSplitScreen
                    ? 'lg:h-[calc(100vh-200px)] lg:min-h-[640px]'
                    : 'lg:h-[calc(100vh-132px)] lg:min-h-[680px]'
                }`}
              >
                {!isSplitScreen && (
                  <div className="lg:col-span-3 h-full min-h-0 flex flex-col">
                    <AlertTriageQueue
                      alerts={filteredAlerts.length > 0 ? filteredAlerts : workspaceState.alerts}
                      forensicsMap={forensicsMap}
                      selectedAlertId={selectedAlert.id}
                      canExecuteBatchTriage={operatorRole === 'L2_CHECKER'}
                      onSelectAlert={handleSelectAlert}
                      onOpenSandbox={() => setActiveView('CASE_BUILDER')}
                      onExecuteBatchTriage={runBatchTriageCluster}
                    />
                  </div>
                )}

                <div
                  className={
                    isSplitScreen
                      ? 'lg:col-span-4 h-full min-h-0 flex flex-col gap-3'
                      : 'lg:col-span-5 h-full min-h-0 flex flex-col gap-3'
                  }
                >
                  <MoneyFlowGraphCanvas
                    alertId={selectedAlert.id}
                    nodes={activeForensics.graphNodes}
                    edges={activeForensics.graphEdges}
                    frozenAccountIds={workspaceState.delta.frozenAccountIds}
                    onSelectEvidenceId={(evId) => setHighlightedEvidenceId(evId)}
                    onTestNodeInWallet={(acc) => {
                      setWalletPrefillAccount(acc);
                      setIsWalletOpen(true);
                    }}
                  />

                  <EvidenceTelemetryTabs
                    alertId={selectedAlert.id}
                    primaryAccountId={selectedAlert.primaryAccountId}
                    inputSpec={activeInputSpec}
                    evidences={workspaceState.evidences}
                    authLogs={workspaceState.authLogs}
                    transactions={workspaceState.transactions}
                    apiEvents={workspaceState.apiEvents}
                    auditLogs={workspaceState.delta.auditLogs}
                    highlightedEvidenceId={highlightedEvidenceId}
                    compactMode={isSplitScreen}
                    isApplyingWhatIf={isInvestigating}
                    onEditCaseSpec={(spec) => openCaseBuilder(spec)}
                    onQuickApplyWhatIf={async (spec) => {
                      const ok = await submitSandboxCase({
                        customTitle: `[What-If] ${spec.customTitle || selectedAlert.title}`,
                        rawTranscript: spec.rawTranscript,
                        imageDataUrl: spec.imageDataUrl,
                        recipientAccountNumber: spec.recipientAccountNumber,
                        recipientOwnerName: spec.recipientOwnerName,
                        amountVnd: spec.amountVnd,
                        caseInputSpec: spec,
                      });
                      return ok;
                    }}
                  />
                </div>

                <div className="lg:col-span-4 h-full min-h-0 flex flex-col">
                  <AiCopilotInvestigationPanel
                    alert={selectedAlert}
                    forensics={activeForensics}
                    report={activeReport}
                    accounts={workspaceState.accounts}
                    transactions={workspaceState.transactions}
                    authLogs={workspaceState.authLogs}
                    devices={workspaceState.devices}
                    auditLogs={workspaceState.delta.auditLogs}
                    operatorRole={operatorRole}
                    isPendingL2Approval={(
                      workspaceState.delta.pendingL2ApprovalAlertIds ?? []
                    ).includes(selectedAlert.id)}
                    analystFeedbackCount={workspaceState.delta.analystFeedbackCount ?? 0}
                    clawbackReceipt={
                      (workspaceState.delta.clawbackReceipts ?? []).find(
                        (c) => c.alertId === selectedAlert.id
                      ) ?? null
                    }
                    isInvestigating={isInvestigating}
                    isApprovingPlaybook={isApprovingPlaybook}
                    chatMessages={chatMessages}
                    isAskingCopilot={isAskingCopilot}
                    onRunInvestigation={() => void runInvestigation()}
                    onApprovePlaybook={() => void approvePlaybook()}
                    onClawbackRefund={() => executeClawbackRefund(selectedAlert.id)}
                    onAnalystOverride={(p) =>
                      submitAnalystOverride({
                        alertId: selectedAlert.id,
                        targetVerdict: p.targetVerdict,
                        reasonVi: p.reasonVi,
                      })
                    }
                    hitlFeedbackMemory={workspaceState.delta.hitlFeedbackMemory ?? []}
                    onCreateHitlFeedback={createHitlFeedback}
                    onModerateHitlFeedback={moderateHitlFeedback}
                    onOpenWallet={() => setIsWalletOpen(true)}
                    onSelectCitation={(evId) => setHighlightedEvidenceId(evId)}
                    onAskCopilot={(q) => void askCopilot(q)}
                  />
                </div>

                {isSplitScreen && (
                  <div className="lg:col-span-4 h-full min-h-0 flex flex-col">
                    <ConsumerWalletSimulator
                      isOpen={true}
                      isSplitDocked={true}
                      prefillAccount={walletPrefillAccount}
                      prefillAmount={walletPrefillAmount}
                      activeShieldRules={workspaceState.delta.activeShieldRules}
                      accounts={workspaceState.accounts}
                      transactions={workspaceState.transactions}
                      lastDecision={lastWalletDecision}
                      onClose={() => setIsSplitScreen(false)}
                      onSimulateTransfer={simulateWalletTransfer}
                      onAcknowledgeDeEscalation={acknowledgeDeEscalationCancel}
                      onEscalateToOps={escalateFromConsumerWallet}
                      onVerifyMerchantReceipt={verifyMerchantManualReceipt}
                      onVerifyMerchantVision={verifyMerchantVisionReceipt}
                    />
                  </div>
                )}
              </div>
            </>
          )}

          {activeView === 'CASE_BUILDER' && (
            <LiveSandboxModal
              isOpen={true}
              asPage={true}
              isSubmitting={isInvestigating}
              initialSpec={sandboxInitialSpec}
              onClose={() => setActiveView('DASHBOARD')}
              onSubmitSandbox={handleSubmitFormAndInspect}
            />
          )}

          {activeView === 'WALLET_SHIELD' && (
            <WalletShieldWorkspaceView
              prefillAccount={walletPrefillAccount}
              prefillAmount={walletPrefillAmount}
              activeShieldRules={workspaceState.delta.activeShieldRules}
              frozenAccountIds={workspaceState.delta.frozenAccountIds}
              accounts={workspaceState.accounts}
              transactions={workspaceState.transactions}
              lastDecision={lastWalletDecision}
              canManageShieldRules={operatorRole === 'L2_CHECKER'}
              onSimulateTransfer={simulateWalletTransfer}
              onAcknowledgeDeEscalation={acknowledgeDeEscalationCancel}
              onToggleShieldRule={toggleShieldRule}
              onAddCustomShieldRule={addCustomShieldRule}
              onEscalateToOps={async (params) => {
                const ok = await escalateFromConsumerWallet(params);
                if (ok) setActiveView('INVESTIGATION');
                return ok;
              }}
              onVerifyMerchantReceipt={verifyMerchantManualReceipt}
              onVerifyMerchantVision={verifyMerchantVisionReceipt}
              onBackToInvestigation={() => setActiveView('INVESTIGATION')}
            />
          )}

          {activeView === 'COMPLIANCE_AUDIT' && (
            <ComplianceAuditWorkspaceView
              alerts={workspaceState.alerts}
              forensicsMap={forensicsMap}
              reportsByAlertId={workspaceState.delta.reportsByAlertId}
              accounts={workspaceState.accounts}
              transactions={workspaceState.transactions}
              authLogs={workspaceState.authLogs}
              devices={workspaceState.devices}
              auditLogs={workspaceState.delta.auditLogs}
              simoAckReceipts={workspaceState.delta.simoAckReceipts ?? []}
              canPushToSimo={operatorRole === 'L2_CHECKER'}
              onPushToSimo={pushDossierToSimo}
            />
          )}
        </main>
      </div>

      {/* Modal Consumer Wallet Simulator (Quick Check from any View) */}
      {!(activeView === 'INVESTIGATION' && isSplitScreen) && activeView !== 'WALLET_SHIELD' && (
        <ConsumerWalletSimulator
          isOpen={isWalletOpen}
          isSplitDocked={false}
          prefillAccount={walletPrefillAccount}
          prefillAmount={walletPrefillAmount}
          activeShieldRules={workspaceState.delta.activeShieldRules}
          accounts={workspaceState.accounts}
          transactions={workspaceState.transactions}
          lastDecision={lastWalletDecision}
          onClose={() => setIsWalletOpen(false)}
          onSimulateTransfer={simulateWalletTransfer}
          onAcknowledgeDeEscalation={acknowledgeDeEscalationCancel}
          onVerifyMerchantReceipt={verifyMerchantManualReceipt}
          onVerifyMerchantVision={verifyMerchantVisionReceipt}
          onEscalateToOps={async (params) => {
            const ok = await escalateFromConsumerWallet(params);
            if (ok) {
              setIsWalletOpen(false);
              setActiveView('INVESTIGATION');
            }
            return ok;
          }}
        />
      )}

      {/* Quick Modal Case Editor when Editing from Investigation / Dashboard */}
      {activeView !== 'CASE_BUILDER' && (
        <LiveSandboxModal
          isOpen={isSandboxOpen}
          asPage={false}
          isSubmitting={isInvestigating}
          initialSpec={sandboxInitialSpec}
          onClose={() => setIsSandboxOpen(false)}
          onSubmitSandbox={handleSubmitFormAndInspect}
        />
      )}

      {/* Enterprise Command Palette (Ctrl + K) */}
      <CommandPaletteModal
        isOpen={isCommandPaletteOpen}
        alerts={workspaceState.alerts}
        operatorRole={operatorRole}
        onClose={() => setIsCommandPaletteOpen(false)}
        onSelectView={(v) => setActiveView(v)}
        onSelectAlertAndInspect={handleOpenAlertInvestigation}
        onRunInvestigation={() => void runInvestigation()}
        onApprovePlaybook={() => void approvePlaybook()}
        onOpenWallet={() => setIsWalletOpen(true)}
        onRunAutoDemo={handleRunAutoPilot}
        onChangeRole={(role) => {
          void setOperatorRole(role).then((ok) => {
            if (ok && role === 'END_USER') setActiveView('WALLET_SHIELD');
          });
        }}
        onResetDemo={resetDemoWorkspace}
      />

      {/* Real-time Floating Toast Alerts */}
      <ToastNotificationStack toasts={toasts} onDismiss={dismissToast} />
    </div>
  );
}
