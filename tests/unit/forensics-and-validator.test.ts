import { describe, expect, it } from 'vitest';
import {
  runDeterministicForensicsSuite,
  type ForensicContext,
} from '@/domain/forensics-analyzers';
import {
  extractEntitiesFromTextDeterministically,
  synthesizeSandboxCase,
} from '@/domain/sandbox-synthesizer';
import { evaluateConsumerTransfer } from '@/domain/shield-evaluator';
import { validateAndRepairCitations } from '@/application/citation-validator';
import {
  SEED_ACCOUNTS,
  SEED_ALERTS,
  SEED_API_EVENTS,
  SEED_AUTH_LOGS,
  SEED_DEVICES,
  SEED_EVIDENCES,
  SEED_TRANSACTIONS,
} from '@/infrastructure/seed-scenarios';
import type { ShieldRule } from '@/domain/types';

const buildContextForAlert = (alertId: string): ForensicContext => {
  const alert = SEED_ALERTS.find((a) => a.id === alertId);
  if (!alert) {
    throw new Error(`Alert ${alertId} not found in seed`);
  }
  return {
    alert,
    accounts: SEED_ACCOUNTS,
    devices: SEED_DEVICES,
    authLogs: SEED_AUTH_LOGS,
    transactions: SEED_TRANSACTIONS,
    apiEvents: SEED_API_EVENTS,
    evidences: SEED_EVIDENCES,
  };
};

describe('AegisOps Layer 1 & 2: Deterministic Forensics Suite & Invariants', () => {
  it('Case 1 (ALT-ATO-001): detects Persistent Session Survival past password reset + 3-Hop Smurfing Mule Ring', () => {
    const suite = runDeterministicForensicsSuite(buildContextForAlert('ALT-ATO-001'));

    expect(suite.deterministicRiskScore).toBeGreaterThanOrEqual(85);
    expect(suite.fallbackReport.classification).toBe('CONFIRMED_ATO_MULE');
    expect(suite.validEvidenceIds).toContain('TXN-8841');
    expect(suite.validEvidenceIds).toContain('LOG-AUTH-302');
    expect(suite.validEvidenceIds).toContain('DEV-EMU-666');

    const graphStep = suite.toolTraceSteps.find((s) => s.toolName === 'trace_money_flow_graph');
    const sessionStep = suite.toolTraceSteps.find((s) => s.toolName === 'inspect_cyber_session_logs');
    expect(graphStep?.status).toBe('CRITICAL');
    expect(sessionStep?.status).toBe('CRITICAL');
    expect(suite.graphNodes.some((n) => n.id === 'DEV-EMU-666')).toBe(true);
  });

  it('Case 2 (ALT-BLG-002): detects Concurrency Race Condition (12x/100ms TOCTOU) & Spoofed Webhook HMAC', () => {
    const suite = runDeterministicForensicsSuite(buildContextForAlert('ALT-BLG-002'));

    expect(suite.fallbackReport.classification).toBe('CONFIRMED_LOGIC_ABUSE');
    expect(suite.validEvidenceIds).toContain('EVT-API-501');
    expect(suite.validEvidenceIds).toContain('EVT-API-502');

    const logicStep = suite.toolTraceSteps.find((s) => s.toolName === 'detect_business_logic_abuse');
    expect(logicStep?.status).toBe('CRITICAL');
    expect(suite.graphNodes.some((n) => n.nodeKind === 'API_ENDPOINT')).toBe(true);
  });

  it('Case 3 (ALT-APP-003): detects Multimodal Fake Police APP Fraud & cross-victim Mule recipient ACC-MULE-903', () => {
    const suite = runDeterministicForensicsSuite(buildContextForAlert('ALT-APP-003'));

    expect(suite.fallbackReport.classification).toBe('CONFIRMED_APP_SCAM');
    expect(suite.validEvidenceIds).toContain('EVD-103');
    expect(suite.validEvidenceIds).toContain('TXN-9011');

    const scamStep = suite.toolTraceSteps.find((s) => s.toolName === 'correlate_scam_campaign');
    expect(scamStep?.status).toBe('CRITICAL');
  });

  it('Case 4 (ALT-FPR-004): protects legitimate night hospital transfer from wrongful account freeze (Human-Centered FP Guard)', () => {
    const suite = runDeterministicForensicsSuite(buildContextForAlert('ALT-FPR-004'));

    expect(suite.fallbackReport.classification).toBe('FALSE_POSITIVE_SAFE');
    expect(suite.deterministicRiskScore).toBeLessThan(25);
    expect(
      suite.fallbackReport.recommendedActions.some(
        (a) => a.actionType === 'MARK_SAFE_FALSE_POSITIVE'
      )
    ).toBe(true);
  });
});

describe('AegisOps Invariant #2 & Red-Team Fix #3: Citation Validator', () => {
  const validIds = ['TXN-8841', 'LOG-AUTH-302', 'DEV-EMU-666', 'EVD-101'];

  it('strips 100% of hallucinated IDs while repairing casing, embedded text, and single-prefix typos', () => {
    const rawAiCitations = [
      'txn-8841', // lowercase -> repaired to TXN-8841
      'Evidence: EVD-101 (SMS spoof)', // wrapped text -> repaired to EVD-101
      'LOG-AUTH-999', // typo on single LOG-AUTH-* prefix -> repaired to LOG-AUTH-302
      'TXN-99999-HALLUCINATED', // fake ID -> stripped!
      'RANDOM-FAKE-ID', // fake ID -> stripped!
    ];

    const cleaned = validateAndRepairCitations(rawAiCitations, validIds);
    expect(cleaned).toEqual(['TXN-8841', 'EVD-101', 'LOG-AUTH-302']);
    expect(cleaned).not.toContain('TXN-99999-HALLUCINATED');
    expect(cleaned).not.toContain('RANDOM-FAKE-ID');
  });

  it('Red-Team Check: backfills deterministic top evidence IDs if LLM returns empty or all-invalid citations', () => {
    const cleaned = validateAndRepairCitations(['FAKE-001', ''], validIds, ['DEV-EMU-666', 'TXN-8841']);
    expect(cleaned).toEqual(['DEV-EMU-666', 'TXN-8841']);
  });
});

describe('AegisOps Red-Team Fix #2 & #1: Live Sandbox Synthesizer & Closed-Loop Consumer Shield', () => {
  it('Red-Team Check: synthesizes non-empty graph & forensics even when Judge uploads image with minimal/empty text', () => {
    const extracted = extractEntitiesFromTextDeterministically(
      'Chuyển gấp 18 triệu vào STK 1903777666555 chủ TK LE VAN TUNG để nhận hoàn tiền shipper http://hoantien-nhanh.vn'
    );
    expect(extracted.recipientAccountNumber).toBe('1903777666555');
    expect(extracted.amountVnd).toBe(18_000_000);

    const bundle = synthesizeSandboxCase({
      rawTranscript: '',
      imageDataUrl: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=',
      extractedOverrides: extracted,
      existingAccounts: SEED_ACCOUNTS,
    });

    const suite = runDeterministicForensicsSuite({
      alert: bundle.alert,
      accounts: [...SEED_ACCOUNTS, bundle.suspectAccount],
      devices: SEED_DEVICES,
      authLogs: SEED_AUTH_LOGS,
      transactions: [...SEED_TRANSACTIONS, bundle.transaction],
      apiEvents: SEED_API_EVENTS,
      evidences: [...SEED_EVIDENCES, bundle.evidence],
    });

    expect(suite.graphNodes.length).toBeGreaterThanOrEqual(3);
    expect(suite.graphEdges.length).toBeGreaterThanOrEqual(2);
    expect(suite.validEvidenceIds).toContain(bundle.transaction.id);
    expect(suite.validEvidenceIds).toContain(bundle.evidence.id);
  });

  it('Closed-Loop Consumer Shield: transitions from WARN/ALLOW before playbook approval to instant BLOCKED_BY_SHIELD after approval', () => {
    // Before Ops approval: no active shield rules yet, but suspicious note triggers smart cooling-off
    const beforeDecision = evaluateConsumerTransfer(
      {
        senderName: 'Phạm Thị Mai (Nạn nhân #4)',
        recipientAccountIdOrNumber: '1903999888777',
        amountVnd: 18_000_000,
        message: 'Chuyen tien xac minh tai san theo yeu cau cong an',
      },
      [],
      SEED_ACCOUNTS
    );
    expect(beforeDecision.decision).toBe('WARN_COOLING_OFF');

    // After Ops Analyst clicks 1-Click Playbook Approval: ShieldRule is active
    const newShield: ShieldRule = {
      id: 'SHD-APP-003',
      alertId: 'ALT-APP-003',
      targetAccountId: 'ACC-MULE-903',
      targetAccountNumber: '1903999888777',
      targetOwnerName: 'TRAN VAN HUNG (TK Tạm Giữ Giả Mạo)',
      ruleType: 'BLOCK_RECIPIENT_MULE',
      userWarningVi: 'CẢNH BÁO ĐỎ: Tài khoản 1903999888777 vừa bị xác nhận thuộc đường dây giả danh Công an lừa đảo!',
      active: true,
      createdAt: new Date().toISOString(),
    };

    const afterDecision = evaluateConsumerTransfer(
      {
        senderName: 'Phạm Thị Mai (Nạn nhân #4)',
        recipientAccountIdOrNumber: '1903999888777',
        amountVnd: 18_000_000,
        message: 'Chuyen khoan binh thuong',
      },
      [newShield],
      SEED_ACCOUNTS
    );
    expect(afterDecision.decision).toBe('BLOCKED_BY_SHIELD');
    expect(afterDecision.matchedRuleId).toBe('SHD-APP-003');
  });

  it('Red-Team Fix #1 (Multi-Lambda Split-Instance & Idempotency): preserves approved Shield across fresh serverless instance via clientDelta and prevents duplicate shields on double-click', async () => {
    const {
      executePlaybookApproval,
      simulateWalletTransferInSession,
    } = await import('@/application/workspace-orchestrator');
    const {
      sanitizePlainText,
      validateImageDataUrl,
    } = await import('@/infrastructure/security-guard');

    // Double-click approval on Lambda Instance #1
    const firstApproval = executePlaybookApproval({
      sessionId: 'lambda-inst-1',
      alertId: 'ALT-APP-003',
    });
    const secondApproval = executePlaybookApproval({
      sessionId: 'lambda-inst-1',
      alertId: 'ALT-APP-003',
      clientDelta: firstApproval.delta,
    });

    // Idempotent: still exactly 1 ShieldRule for ALT-APP-003
    const app003Shields = secondApproval.delta.activeShieldRules.filter(
      (r) => r.id === 'SHD-ALT-APP-003'
    );
    expect(app003Shields).toHaveLength(1);

    // Simulate cold Lambda Instance #2 starting with empty memory for the SAME sessionId and restoring via signed clientDelta
    const { evictServerSessionForColdStartTest } = await import('@/infrastructure/workspace-store');
    evictServerSessionForColdStartTest('lambda-inst-1');
    const coldInstanceCheck = simulateWalletTransferInSession({
      sessionId: 'lambda-inst-1',
      transfer: {
        senderName: 'Nạn nhân #4',
        recipientAccountIdOrNumber: '1903999888777',
        amountVnd: 25_000_000,
        message: 'Chuyen khoan',
      },
      clientDelta: secondApproval.delta,
    });

    expect(coldInstanceCheck.decision.decision).toBe('BLOCKED_BY_SHIELD');
    expect(coldInstanceCheck.decision.matchedRuleId).toBe('SHD-ALT-APP-003');

    // Security Guard Red-Team checks (XSS & invalid MIME upload)
    expect(sanitizePlainText('<script>alert(1)</script>Hello')).toBe('scriptalert(1)/scriptHello');
    expect(validateImageDataUrl('data:text/html;base64,PHNjcmlwdD4=').valid).toBe(false);
    expect(validateImageDataUrl('data:image/png;base64,iVBORw0KGgo=').valid).toBe(true);
  });

  it('Compliance Incident Dossier Generator: strips any unverified citations and produces complete regulatory Markdown dossier even with empty audit logs', async () => {
    const { buildComplianceIncidentDossier } = await import('@/domain/compliance-report');
    const ctx = buildContextForAlert('ALT-APP-003');
    const forensics = runDeterministicForensicsSuite(ctx);

    const dossier = buildComplianceIncidentDossier({
      alert: ctx.alert,
      forensics,
      report: {
        ...forensics.fallbackReport,
        citedEvidenceIds: ['EVD-103', 'TXN-9011', 'HALLUCINATED-ID-999'],
      },
      auditLogs: [],
    });

    expect(dossier.dossierId).toBe('DOS-ALT-APP-003');
    expect(dossier.verifiedEvidenceList.map((e) => e.id)).toContain('EVD-103');
    expect(dossier.verifiedEvidenceList.map((e) => e.id)).not.toContain('HALLUCINATED-ID-999');
    expect(dossier.markdownText).toContain('BIÊN BẢN ĐIỀU TRA & XỬ LÝ SỰ CỐ AN NINH FINTECH');
  });

  it('Top-5 Upgrade #1, #3 & #4: computes quantitative Smurfing Entropy, SHAP-like Trust Dampeners, 3 Visual Sandbox Samples, and Psychological De-escalation Cards', async () => {
    const { SANDBOX_VISUAL_GALLERY } = await import('@/infrastructure/sandbox-gallery');
    const { validateImageDataUrl } = await import('@/infrastructure/security-guard');

    // 1. Quantitative Smurfing Entropy on ALT-ATO-001 (3 equal 16M transfers -> entropy ~ 0.99)
    const atoSuite = runDeterministicForensicsSuite(buildContextForAlert('ALT-ATO-001'));
    expect(atoSuite.quantitativeMetrics.smurfingEntropyIndex).toBeGreaterThanOrEqual(0.95);
    expect(atoSuite.quantitativeMetrics.deviceBipartiteClusterScore).toBeGreaterThanOrEqual(0.8);

    // 2. SHAP-like Risk Boosters vs. Trust Dampeners on ALT-FPR-004 (Hospital transfer)
    const fpSuite = runDeterministicForensicsSuite(buildContextForAlert('ALT-FPR-004'));
    const hasBooster = fpSuite.riskAttributionFactors.some((f) => f.kind === 'RISK_BOOSTER' && f.deltaScore > 0);
    const hasDampener = fpSuite.riskAttributionFactors.some((f) => f.kind === 'TRUST_DAMPENER' && f.deltaScore < 0);
    expect(hasBooster).toBe(true);
    expect(hasDampener).toBe(true);
    expect(fpSuite.deterministicRiskScore).toBeLessThan(25);

    // 3. All 3 pre-bundled Multimodal Sandbox Visual Samples pass security guard & synthesize valid graphs
    expect(SANDBOX_VISUAL_GALLERY).toHaveLength(3);
    for (const sample of SANDBOX_VISUAL_GALLERY) {
      expect(validateImageDataUrl(sample.imageDataUrl).valid).toBe(true);
      const bundle = synthesizeSandboxCase({
        customTitle: sample.title,
        rawTranscript: sample.transcript,
        imageDataUrl: sample.imageDataUrl,
        existingAccounts: SEED_ACCOUNTS,
      });
      expect(bundle.extracted.recipientAccountNumber).toBe(sample.recipientAccountNumber);
    }

    // 4. Psychological De-escalation Card on blocked or warned transfer
    const decision = evaluateConsumerTransfer(
      {
        senderName: 'Nạn nhân #4',
        recipientAccountIdOrNumber: '1903777666555',
        amountVnd: 18_500_000,
        message: 'Chuyen khoan hoan tien shipper',
      },
      [],
      SEED_ACCOUNTS
    );
    expect(decision.decision).toBe('WARN_COOLING_OFF');
    expect(decision.deEscalationCardVi).toBeDefined();
    expect(decision.deEscalationCardVi?.realityChecklistVi.length).toBeGreaterThanOrEqual(2);
  });

  it('MoMo/SBV Regulatory Upgrades A, B & C: detects VietQR NAPAS Name-Check Mismatch, In-Call Behavioral Telemetry, and Decree 13 PII-Masked SIMO payload', async () => {
    const { inspectVietQrSample } = await import('@/domain/vietqr-inspector');
    const { buildComplianceIncidentDossier } = await import('@/domain/compliance-report');

    // Upgrade B: VietQR Inspector
    const spoofQr = inspectVietQrSample('QR-SPOOF-GHN');
    expect(spoofQr.nameMismatchDetected).toBe(true);
    expect(spoofQr.riskVerdict).toBe('CRITICAL_QR_SPOOF');
    expect(spoofQr.recipientAccountNumber).toBe('1903999888777');

    const safeQr = inspectVietQrSample('QR-HOSPITAL-SAFE');
    expect(safeQr.nameMismatchDetected).toBe(false);
    expect(safeQr.riskVerdict).toBe('VERIFIED_MERCHANT_QR');

    // Upgrade A & C: SBV QĐ 2345, TT 50, Decree 13 PII Masking in SIMO Report
    const ctx = buildContextForAlert('ALT-APP-003');
    const forensics = runDeterministicForensicsSuite(ctx);
    const dossier = buildComplianceIncidentDossier({
      alert: ctx.alert,
      forensics,
      report: forensics.fallbackReport,
      auditLogs: [],
    });

    expect(dossier.regulatoryReferencesVi.some((r) => r.includes('2345/QĐ-NHNN'))).toBe(true);
    expect(dossier.regulatoryReferencesVi.some((r) => r.includes('50/2024/TT-NHNN'))).toBe(true);
    expect(dossier.simoPiiMaskedPayload.victimAccountMasked).toContain('***');
    expect(dossier.simoPiiMaskedPayload.victimIdentityHashSha256).toMatch(/^[0-9a-f]{64}$/);
  });

  it('Multi-Victim & Co-Conspirator Graph Topology: renders all Fan-In victims (ACC-USR-103 & ACC-USR-105) plus sibling Mule accounts sharing DEV-EMU-666', () => {
    const suite = runDeterministicForensicsSuite(buildContextForAlert('ALT-APP-003'));
    const nodeIds = suite.graphNodes.map((n) => n.id);

    expect(nodeIds).toContain('ACC-USR-103'); // Victim #1
    expect(nodeIds).toContain('ACC-USR-105'); // Victim #2 (Fan-In cross victim)
    expect(nodeIds).toContain('ACC-MULE-903'); // Primary Mule recipient
    expect(nodeIds).toContain('DEV-EMU-666'); // Shared rooted emulator
    expect(nodeIds).toContain('ACC-MULE-901'); // Sibling Mule co-conspirator #1
    expect(nodeIds).toContain('ACC-MULE-902'); // Sibling Mule co-conspirator #2
    expect(suite.graphNodes.length).toBeGreaterThanOrEqual(6);
  });

  it('MoMo 3-Color Trust Traffic Light (GREEN/YELLOW/RED): transitions from YELLOW to RED after Shield activation and shows GREEN for verified hospital', async () => {
    const { evaluateRecipientTrustTrafficLight } = await import('@/domain/shield-evaluator');

    // 1. Before Ops approval -> YELLOW (New mule suspect account, age 9 days)
    const beforeLight = evaluateRecipientTrustTrafficLight('1903999888777', [], SEED_ACCOUNTS);
    expect(beforeLight.color).toBe('YELLOW');

    // 2. After Ops approval -> RED (Active Aegis Shield Rule)
    const shieldRule: ShieldRule = {
      id: 'SHD-ALT-APP-003',
      alertId: 'ALT-APP-003',
      targetAccountId: 'ACC-MULE-903',
      targetAccountNumber: '1903999888777',
      targetOwnerName: 'TRAN VAN HUNG',
      ruleType: 'BLOCK_RECIPIENT_MULE',
      userWarningVi: 'Blocked',
      active: true,
      createdAt: new Date().toISOString(),
    };
    const afterLight = evaluateRecipientTrustTrafficLight('1903999888777', [shieldRule], SEED_ACCOUNTS);
    expect(afterLight.color).toBe('RED');

    // 3. Trusted Hospital -> GREEN
    const safeLight = evaluateRecipientTrustTrafficLight('1188999000888', [shieldRule], SEED_ACCOUNTS);
    expect(safeLight.color).toBe('GREEN');
  });

  it('Cross-Case Campaign Correlator & Batch Triage: links ALT-APP-003 and ALT-ATO-001 via shared DEV-EMU-666 and flags ALT-FPR-004 for Auto-Clear', async () => {
    const { computeCrossCaseCorrelations } = await import('@/domain/campaign-correlator');
    const forensicsMap: Record<string, ReturnType<typeof runDeterministicForensicsSuite>> = {};
    for (const alert of SEED_ALERTS) {
      forensicsMap[alert.id] = runDeterministicForensicsSuite(buildContextForAlert(alert.id));
    }

    const triage = computeCrossCaseCorrelations(SEED_ALERTS, forensicsMap);
    expect(triage.linkedCampaignClusters.length).toBeGreaterThanOrEqual(1);
    expect(triage.correlationsByAlertId['ALT-APP-003']?.linkedAlertIds).toContain('ALT-ATO-001');
    expect(triage.correlationsByAlertId['ALT-APP-003']?.sharedInfrastructureIds).toContain('DEV-EMU-666');
    expect(triage.autoClearCandidateIds).toContain('ALT-FPR-004');
  });

  it('Commercial 4-Part Case Builder (Preset 1 — Safe Partner Transfer): dynamically computes low risk score (<25) and FALSE_POSITIVE_SAFE without hardcoding', async () => {
    const { CASE_BUILDER_PRESETS, evaluateLiveCaseInputPreview } = await import(
      '@/domain/sandbox-synthesizer'
    );
    const safePreset = CASE_BUILDER_PRESETS.find((p) => p.id === 'PRESET-SAFE')!;
    const preview = evaluateLiveCaseInputPreview(safePreset.spec, SEED_ACCOUNTS);

    expect(preview.riskScore).toBeLessThan(25);
    expect(preview.classification).toBe('FALSE_POSITIVE_SAFE');
    expect(preview.factors.some((f) => f.kind === 'TRUST_DAMPENER')).toBe(true);
  });

  it('Commercial 4-Part Case Builder (Preset 3 — Custom ATO + 3-Hop Smurfing): dynamically synthesizes 3 transactions, high Smurfing Entropy, and CONFIRMED_ATO_MULE', async () => {
    const { CASE_BUILDER_PRESETS, synthesizeSandboxCase } = await import(
      '@/domain/sandbox-synthesizer'
    );
    const atoPreset = CASE_BUILDER_PRESETS.find((p) => p.id === 'PRESET-CYBER-ATO')!;
    const bundle = synthesizeSandboxCase({
      rawTranscript: atoPreset.spec.rawTranscript,
      caseInputSpec: atoPreset.spec,
      existingAccounts: SEED_ACCOUNTS,
    });

    expect(bundle.transactions.length).toBeGreaterThanOrEqual(3);
    expect(bundle.alert.deterministicRiskScore).toBeGreaterThanOrEqual(85);
    expect(bundle.computedForensics.fallbackReport.classification).toBe('CONFIRMED_ATO_MULE');
    expect(bundle.computedForensics.quantitativeMetrics.smurfingEntropyIndex).toBeGreaterThanOrEqual(0.95);
  });

  it('Commercial 4-Part Case Builder (Preset 4 — API Race Condition & deriveCaseInputSpecFromAlert): dynamically detects API exploit and round-trips input spec', async () => {
    const {
      CASE_BUILDER_PRESETS,
      deriveCaseInputSpecFromAlert,
      evaluateLiveCaseInputPreview,
    } = await import('@/domain/sandbox-synthesizer');
    const racePreset = CASE_BUILDER_PRESETS.find((p) => p.id === 'PRESET-RACE-LOGIC')!;
    const preview = evaluateLiveCaseInputPreview(racePreset.spec, SEED_ACCOUNTS);

    expect(preview.classification).toBe('CONFIRMED_LOGIC_ABUSE');
    expect(preview.riskScore).toBeGreaterThanOrEqual(75);

    const derived = deriveCaseInputSpecFromAlert({
      alert: SEED_ALERTS[0]!,
      accounts: SEED_ACCOUNTS,
      devices: SEED_DEVICES,
      authLogs: SEED_AUTH_LOGS,
      transactions: SEED_TRANSACTIONS,
      apiEvents: SEED_API_EVENTS,
      evidences: SEED_EVIDENCES,
    });
    expect(derived.recipientAccountNumber).toBeTruthy();
    expect(derived.amountVnd).toBeGreaterThan(0);
  });

  it('Commercial Upgrade — Batch CSV/JSON I/O: parses sample CSV template, imports batch cases with real forensics, and exports UTF-8 BOM CSV report', async () => {
    const {
      exportCasesToCsv,
      generateSampleBatchCsv,
      parseBatchCasesPayload,
    } = await import('@/domain/batch-io');
    const { ingestBatchSandboxCases } = await import('@/application/workspace-orchestrator');

    const sampleCsv = generateSampleBatchCsv();
    const { specs } = parseBatchCasesPayload(sampleCsv, 'AegisOps_Batch_Template.csv');
    expect(specs).toHaveLength(3);

    const imported = ingestBatchSandboxCases({
      sessionId: 'batch-test-session',
      specs,
      fileName: 'AegisOps_Batch_Template.csv',
    });
    expect(imported.importedCount).toBe(3);
    expect(imported.createdAlertIds).toHaveLength(3);
    expect(imported.delta.customAlerts).toHaveLength(3);

    // Verify Safe Hospital row inside CSV gets <25 score while Fraud & ATO rows get >=85
    const safeAlert = imported.delta.customAlerts.find((a) => a.title.includes('Học phí'));
    const scamAlert = imported.delta.customAlerts.find((a) => a.title.includes('Shipper'));
    expect(safeAlert?.deterministicRiskScore).toBeLessThan(25);
    expect(scamAlert?.deterministicRiskScore).toBeGreaterThanOrEqual(85);

    const csvOut = exportCasesToCsv(SEED_ALERTS, SEED_ACCOUNTS, {});
    expect(csvOut.startsWith('\uFEFFAlertId,Title')).toBe(true);
    expect(csvOut).toContain('ALT-APP-003');
  });

  it('Commercial Upgrade — Banking Maker-Checker (Four-Eyes Principle): L1 Maker proposes without freezing account until L2 Checker approves', async () => {
    const { executePlaybookApproval } = await import('@/application/workspace-orchestrator');

    // Step 1: L1 Maker proposes Playbook -> pending L2 approval, 0 frozen accounts, 0 active shields
    const l1Proposal = executePlaybookApproval({
      sessionId: 'maker-checker-session',
      alertId: 'ALT-APP-003',
      mode: 'PROPOSE_L1',
    });
    expect(l1Proposal.proposedForL2).toBe(true);
    expect(l1Proposal.newStatus).toBe('INVESTIGATING');
    expect(l1Proposal.delta.pendingL2ApprovalAlertIds).toContain('ALT-APP-003');
    expect(l1Proposal.delta.activeShieldRules).toHaveLength(0);
    expect(l1Proposal.delta.frozenAccountIds).toHaveLength(0);

    // Step 2: L2 Checker approves -> clears pending flag, freezes Mule & activates Community Shield
    const l2Approval = executePlaybookApproval({
      sessionId: 'maker-checker-session',
      alertId: 'ALT-APP-003',
      mode: 'APPROVE_L2',
      clientDelta: l1Proposal.delta,
    });
    expect(l2Approval.newStatus).toBe('MITIGATED');
    expect(l2Approval.delta.pendingL2ApprovalAlertIds).not.toContain('ALT-APP-003');
    expect(l2Approval.delta.activeShieldRules.length).toBeGreaterThanOrEqual(1);
    expect(l2Approval.delta.frozenAccountIds).toContain('ACC-MULE-903');
  });

  it('Top UX Upgrades #1 & #3: supports Victim Self-Rescue KPI tracking and Shield Rule Pause/Resume & Custom Block Rule', async () => {
    const {
      addCustomShieldRuleInSession,
      executePlaybookApproval,
      recordVictimSelfRescueInSession,
      simulateWalletTransferInSession,
      toggleShieldRuleInSession,
    } = await import('@/application/workspace-orchestrator');

    // 1. Activate Shield Rule on ALT-APP-003
    const approved = executePlaybookApproval({
      sessionId: 'ux-upgrade-session',
      alertId: 'ALT-APP-003',
    });
    const ruleId = approved.createdShieldRule!.id;

    // 2. Toggle Pause -> transfer should WARN instead of BLOCKED_BY_SHIELD
    const paused = toggleShieldRuleInSession({
      sessionId: 'ux-upgrade-session',
      ruleId,
      clientDelta: approved.delta,
    });
    expect(paused.updatedRule.active).toBe(false);
    const duringPause = simulateWalletTransferInSession({
      sessionId: 'ux-upgrade-session',
      transfer: {
        senderName: 'Khách hàng Test',
        recipientAccountIdOrNumber: '1903999888777',
        amountVnd: 18_000_000,
        message: 'Chuyen tien xac minh cong an',
      },
      clientDelta: paused.delta,
    });
    expect(duringPause.decision.decision).toBe('WARN_COOLING_OFF');

    // 3. Toggle Resume -> instant BLOCKED_BY_SHIELD
    const resumed = toggleShieldRuleInSession({
      sessionId: 'ux-upgrade-session',
      ruleId,
      clientDelta: duringPause.delta,
    });
    expect(resumed.updatedRule.active).toBe(true);
    const afterResume = simulateWalletTransferInSession({
      sessionId: 'ux-upgrade-session',
      transfer: {
        senderName: 'Khách hàng Test',
        recipientAccountIdOrNumber: '1903999888777',
        amountVnd: 18_000_000,
        message: 'Chuyen tien',
      },
      clientDelta: resumed.delta,
    });
    expect(afterResume.decision.decision).toBe('BLOCKED_BY_SHIELD');

    // 4. Add Custom Shield Rule -> blocks new arbitrary account immediately
    const customAdded = addCustomShieldRuleInSession({
      sessionId: 'ux-upgrade-session',
      targetAccountNumber: '1903000999888',
      targetOwnerName: 'NGUYEN VAN SCAM',
      clientDelta: afterResume.delta,
    });
    const customBlocked = simulateWalletTransferInSession({
      sessionId: 'ux-upgrade-session',
      transfer: {
        senderName: 'Khách hàng Test',
        recipientAccountIdOrNumber: '1903000999888',
        amountVnd: 9_000_000,
        message: 'Chuyen tien',
      },
      clientDelta: customAdded.delta,
    });
    expect(customBlocked.decision.decision).toBe('BLOCKED_BY_SHIELD');

    // 5. Victim Self-Rescue -> adds saved VND & logs VICTIM_SELF_RESCUED_DEESCALATION
    const rescued = recordVictimSelfRescueInSession({
      sessionId: 'ux-upgrade-session',
      recipientAccount: '1903000999888',
      amountVnd: 9_000_000,
      clientDelta: customBlocked.delta,
    });
    expect(rescued.savedTotalVnd).toBe(9_000_000);
    expect(
      rescued.delta.auditLogs.some((l) => l.action === 'VICTIM_SELF_RESCUED_DEESCALATION')
    ).toBe(true);
  });

  it('Market Research Upgrade #1: Real EMVCo VietQR TLV Parser decodes Tag 38/54/62 & catches Brand-vs-NAPAS Owner Spoofing', async () => {
    const { parseEmvTlvSegments, parseRawEmvVietQrPayload } = await import(
      '@/domain/vietqr-inspector'
    );

    const payload =
      '00020101021238570010A00000072701270006970407011319039998887770208QRIBFTTA53037045408180000005802VN62300826XAC MINH TAI SAN HOAN TIEN6304A9F2';
    const topTags = parseEmvTlvSegments(payload);
    expect(topTags['53']).toBe('704');
    expect(topTags['54']).toBe('18000000');
    expect(topTags['58']).toBe('VN');

    const decodedSpoof = parseRawEmvVietQrPayload({
      rawPayload: payload,
      displayedBrandName: 'CỔNG HOÀN TIỀN SHOPEE EXPRESS',
    });
    expect(decodedSpoof.recipientAccountNumber).toBe('1903999888777');
    expect(decodedSpoof.amountVnd).toBe(18_000_000);
    expect(decodedSpoof.nameMismatchDetected).toBe(true);
    expect(decodedSpoof.riskVerdict).toBe('CRITICAL_QR_SPOOF');
  });

  it('Market Research Upgrade #2: 1-Click Batch Triage freezes linked DEV-EMU-666 cluster (ALT-APP-003 & ALT-ATO-001) & Auto-Clears ALT-FPR-004', async () => {
    const { executeBatchTriageInSession } = await import('@/application/workspace-orchestrator');

    const res = executeBatchTriageInSession({ sessionId: 'batch-triage-test' });
    expect(res.clusteredMitigatedIds).toContain('ALT-APP-003');
    expect(res.clusteredMitigatedIds).toContain('ALT-ATO-001');
    expect(res.autoClearedSafeIds).toContain('ALT-FPR-004');
    expect(res.delta.alertStatuses['ALT-APP-003']).toBe('MITIGATED');
    expect(res.delta.alertStatuses['ALT-ATO-001']).toBe('MITIGATED');
    expect(res.delta.alertStatuses['ALT-FPR-004']).toBe('DISMISSED_SAFE');
  });

  it('Market Research Upgrade #3: Anti-Deepfake & Virtual Camera Injection (ISO 30107-3 Liveness PAD) flags critical cyber risk', async () => {
    const { synthesizeSandboxCase } = await import('@/domain/sandbox-synthesizer');

    const bundle = synthesizeSandboxCase({
      rawTranscript: 'Chuyen khoan xac thuc khuon mat qua camera ao',
      caseInputSpec: {
        senderName: 'Khách hàng Deepfake Target',
        senderAccountNumber: '0901222333',
        senderAvgTxVnd: 800_000,
        amountVnd: 20_000_000,
        recipientAccountNumber: '1903888999000',
        recipientOwnerName: 'BENH VIEN TEST',
        recipientAccountType: 'TRUSTED_INSTITUTION',
        deepfakeOrVirtualCamDetected: true,
      },
      existingAccounts: SEED_ACCOUNTS,
    });

    const cyberStep = bundle.computedForensics.toolTraceSteps.find(
      (s) => s.toolName === 'inspect_cyber_session_logs'
    );
    expect(cyberStep?.status).toBe('CRITICAL');
    expect(cyberStep?.summaryVi).toContain('ISO/IEC 30107-3');
    expect(bundle.computedForensics.fallbackReport.classification).toBe('CONFIRMED_ATO_MULE');
  });

  it('Market Research Upgrades #4 & #5: Analyst HITL Override (Unfreeze Safe & Force Block) + 1-Click Push to SBV SIMO Registry', async () => {
    const {
      executeAnalystOverrideInSession,
      executePlaybookApproval,
      pushDossierToSimoInSession,
    } = await import('@/application/workspace-orchestrator');

    // First mitigate ALT-APP-003, then HITL Override SAFE -> unlocks account & increments feedback counter
    const approved = executePlaybookApproval({
      sessionId: 'hitl-simo-session',
      alertId: 'ALT-APP-003',
    });
    const overSafe = executeAnalystOverrideInSession({
      sessionId: 'hitl-simo-session',
      alertId: 'ALT-APP-003',
      targetVerdict: 'OVERRIDE_SAFE',
      reasonVi: 'Xác minh trực tiếp chủ tài khoản giao dịch thật',
      clientDelta: approved.delta,
    });
    expect(overSafe.delta.alertStatuses['ALT-APP-003']).toBe('DISMISSED_SAFE');
    expect(overSafe.delta.analystFeedbackCount).toBe(1);
    expect(overSafe.delta.activeShieldRules.some((r) => r.alertId === 'ALT-APP-003')).toBe(false);

    // Push ALT-ATO-001 to SBV SIMO Registry -> returns SIMO-ACK-2026-* receipt with real 64-hex SHA-256 & HMAC pseudonym
    const simoPush = pushDossierToSimoInSession({
      sessionId: 'hitl-simo-session',
      alertId: 'ALT-ATO-001',
      clientDelta: overSafe.delta,
    });
    expect(simoPush.receipt.receiptId).toMatch(/^SIMO-ACK-2026-/);
    expect(simoPush.receipt.victimIdentityHashSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(simoPush.receipt.victimPseudonymHmacSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(simoPush.delta.simoAckReceipts).toHaveLength(1);
  });

  it('Phase 14 Upgrade #1: MoMo Merchant Soundbox & Fake Bill Photoshop Verifier detects 1.000đ -> 15M mismatch, missing TXN, and authentic Core Ledger transfer', async () => {
    const { verifyMerchantBillReceipt } = await import('@/domain/merchant-verifier');

    // 1. Classic 1.000₫ -> 15.000.000₫ Photoshopped receipt mismatch
    const forged = verifyMerchantBillReceipt({
      claimedTxId: 'TXN-MERCH-1K',
      claimedAmountVnd: 15_000_000,
      ledgerTransactions: SEED_TRANSACTIONS,
      accounts: SEED_ACCOUNTS,
    });
    expect(forged.verdict).toBe('FORGED_PHOTOSHOP_AMOUNT_MISMATCH');
    expect(forged.actualLedgerAmountVnd).toBe(1_000);

    // 2. Non-existent ghost transaction ID
    const ghost = verifyMerchantBillReceipt({
      claimedTxId: 'TXN-GHOST-999',
      claimedAmountVnd: 12_500_000,
      ledgerTransactions: SEED_TRANSACTIONS,
      accounts: SEED_ACCOUNTS,
    });
    expect(ghost.verdict).toBe('FAKE_RECEIPT_NOT_IN_LEDGER');

    // 3. Authentic Core Ledger transaction
    const verified = verifyMerchantBillReceipt({
      claimedTxId: 'TXN-MERCH-OK',
      claimedAmountVnd: 4_850_000,
      ledgerTransactions: SEED_TRANSACTIONS,
      accounts: SEED_ACCOUNTS,
    });
    expect(verified.verdict).toBe('VERIFIED_LEDGER_MATCH');
    expect(verified.soundboxAnnouncementVi).toContain('4.850.000');
  });

  it('Phase 14 Upgrades #2 & #3: Golden-Window Clawback & Refund Recovery + Phishing URL / Malicious APK Threat Scanner', async () => {
    const { inspectMaliciousUrlsAndApks } = await import('@/domain/forensics-analyzers');
    const { executeClawbackAndRefundInSession } = await import(
      '@/application/workspace-orchestrator'
    );

    // URL & APK Threat Scanner
    const urlFindings = inspectMaliciousUrlsAndApks(
      'Truy cập http://dichvucong-capnhat.vn/lenh-bat.apk hoặc https://momo.vn để kiểm tra'
    );
    const malicious = urlFindings.find((u) => u.isApkPayload);
    const safeOfficial = urlFindings.find((u) => u.domain === 'momo.vn');
    expect(malicious?.verdict).toBe('MALICIOUS_APK_PHISHING');
    expect(malicious?.riskScore).toBeGreaterThanOrEqual(80);
    expect(safeOfficial?.verdict).toBe('SAFE_OFFICIAL');

    // HELD TXN-8843 (no settlement posting) MUST NOT be clawed back;
    // Settled COMPLETED TXN-8841 (16.000.000đ, ACC-USR-101 -> ACC-MULE-901) IS eligible for clawback!
    expect(() =>
      executeClawbackAndRefundInSession({
        sessionId: 'clawback-test-session',
        alertId: 'ALT-ATO-001',
        originalTxId: 'TXN-8843',
      })
    ).toThrow();

    const clawback = executeClawbackAndRefundInSession({
      sessionId: 'clawback-test-session',
      alertId: 'ALT-ATO-001',
      originalTxId: 'TXN-8841',
    });
    expect(clawback.clawbackReceipt.clawbackId).toMatch(/^CLAWBACK-2026-/);
    expect(clawback.clawbackReceipt.recoveredAmountVnd).toBe(16_000_000);
    expect(clawback.clawbackReceipt.txIds).toContain('TXN-8841');

    // Safety guard: reject clawback on legitimate ALT-FPR-004 hospital transaction
    expect(() =>
      executeClawbackAndRefundInSession({
        sessionId: 'clawback-test-session',
        alertId: 'ALT-FPR-004',
        clientDelta: clawback.delta,
      })
    ).toThrow();
  });
});
