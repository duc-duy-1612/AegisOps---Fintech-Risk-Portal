import { expect, test, type Page } from '@playwright/test';

const attachRuntimeHealthGuards = (page: Page) => {
  const consoleErrors: string[] = [];
  const pageErrors: string[] = [];
  const failed5xxResponses: string[] = [];

  page.on('console', (msg) => {
    if (msg.type() === 'error') {
      const text = msg.text();
      if (!text.includes('speechSynthesis')) {
        consoleErrors.push(text);
      }
    }
  });

  page.on('pageerror', (err) => {
    pageErrors.push(err.message);
  });

  page.on('response', (res) => {
    if (res.status() >= 500) {
      failed5xxResponses.push(`${res.status()} ${res.url()}`);
    }
  });

  return {
    assertClean: () => {
      const hydrationErrors = consoleErrors.filter((c) =>
        /hydration|did not match|server rendered html/i.test(c)
      );
      expect(hydrationErrors, `Hydration warnings detected: ${hydrationErrors.join('; ')}`).toEqual([]);
      expect(pageErrors, `Uncaught pageerrors: ${pageErrors.join('; ')}`).toEqual([]);
      expect(consoleErrors, `Console errors: ${consoleErrors.join('; ')}`).toEqual([]);
      expect(failed5xxResponses, `HTTP 5xx responses: ${failed5xxResponses.join('; ')}`).toEqual([]);
    },
  };
};

test.describe('AegisOps Wave 2 — 7 Golden Path E2E Scenarios', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');
  });

  test('Scenario 1: Investigation -> AI Analysis -> L2 Approve -> P2P Transfer BLOCKED with unchanged balance', async ({
    page,
  }) => {
    const guard = attachRuntimeHealthGuards(page);

    // Verify E2E server starts in isolated local-only AI mode (no external Gemini circuit opened)
    const healthBefore = await page.request.get('/api/health');
    expect(healthBefore.status()).toBe(200);
    const healthBeforeJson = await healthBefore.json();
    expect(healthBeforeJson.aiMode).toBe('AI_UNCONFIGURED');
    expect(healthBeforeJson.aiEngineReady).toBe(false);
    expect(healthBeforeJson.aiCircuit?.state).toBe('CLOSED');

    // Go to Trung tâm Điều tra
    await page.getByRole('button', { name: /Trung tâm Điều tra/i }).click();

    // Run AI Investigation on ALT-APP-003 (must complete via local deterministic fallback with zero external Gemini call)
    const investigateResponsePromise = page.waitForResponse(
      (res) => res.url().includes('/api/investigate') && res.request().method() === 'POST'
    );
    await page.getByRole('button', { name: /Bước 1: Chạy AI Điều tra/i }).click();
    const investigateRes = await investigateResponsePromise;
    expect(investigateRes.status()).toBe(200);
    const investigateJson = await investigateRes.json();
    expect(investigateJson.report?.modelUsed).toBe('deterministic-forensics-engine-v2');
    await expect(
      page.getByRole('button', { name: /Bước 2: Duyệt & Bật Lá chắn/i })
    ).toBeVisible({ timeout: 25_000 });
    await expect(page.getByTestId('ai-source-badge')).toContainText(/Chế độ Dự phòng Định lượng/i);

    const healthAfter = await page.request.get('/api/health');
    expect(healthAfter.status()).toBe(200);
    const healthAfterJson = await healthAfter.json();
    expect(healthAfterJson.aiMode).toBe('AI_UNCONFIGURED');
    expect(healthAfterJson.aiCircuit?.state).toBe('CLOSED');

    // L2 Approve Playbook -> Activates Shield on 1903999888777
    await page.getByRole('button', { name: /Bước 2: Duyệt & Bật Lá chắn/i }).click();
    await expect(
      page.getByRole('button', { name: /Bước 3: Mở Ví Kiểm chứng Chặn Ngay/i })
    ).toBeVisible();

    // Open Consumer Wallet Simulator
    await page.getByRole('button', { name: /Bước 3: Mở Ví Kiểm chứng Chặn Ngay/i }).click();
    const balanceBefore = await page.getByTestId('wallet-live-balance').innerText();
    expect(balanceBefore).toContain('45.000.000');

    // Attempt P2P Transfer to blocked mule 1903999888777
    await page.getByRole('button', { name: /Xác nhận Chuyển/i }).click();
    await expect(page.getByText(/Giao dịch bị chặn bởi Lá chắn Aegis Shield/i)).toBeVisible();

    // Balance must remain 45.000.000 ₫ (no money moved)
    await expect(page.getByTestId('wallet-live-balance')).toContainText('45.000.000');
    guard.assertClean();
  });

  test('Scenario 2: Maker-Checker RBAC Enforcement (L1_MAKER cannot directly approve L2 / execute Batch Triage)', async ({
    page,
  }) => {
    const guard = attachRuntimeHealthGuards(page);

    await page.getByRole('button', { name: /Trung tâm Điều tra/i }).click();
    await page.getByRole('button', { name: /Bước 1: Chạy AI Điều tra/i }).click();

    // Switch persona to L1_MAKER
    await page.locator('#sidebar-role-select').selectOption('L1_MAKER');
    await expect(
      page.getByRole('button', { name: /B3: Trình Playbook lên L2 \(Maker\)/i })
    ).toBeVisible();

    // Propose L1 -> puts alert into Pending L2 state
    await page.getByRole('button', { name: /B3: Trình Playbook lên L2 \(Maker\)/i }).click();
    await expect(page.getByText(/Chờ L2 phê duyệt/i).first()).toBeVisible();

    // Open Gom nhóm AI while L1 -> execution button locked for L1
    await page.getByRole('button', { name: /Gom nhóm AI/i }).click();
    await expect(
      page.getByText(/Chỉ Quản lý Rủi ro L2 \(Checker\) mới được thực thi Gom nhóm 1-Chạm/i)
    ).toBeVisible();

    // Switch back to L2_CHECKER
    await page.locator('#sidebar-role-select').selectOption('L2_CHECKER');
    await expect(
      page.getByRole('button', { name: /L2 Phê duyệt & Bật Lá chắn/i })
    ).toBeVisible();
    guard.assertClean();
  });

  test('Scenario 3: Unified Ledger P2P Settlement + Live Balance Deduction + All 5 Merchant Soundbox Cases (A-E)', async ({
    page,
  }) => {
    const guard = attachRuntimeHealthGuards(page);

    await page.getByRole('button', { name: /Ví & Lá chắn Người dùng/i }).click();
    await expect(page.getByTestId('wallet-live-balance')).toContainText('45.000.000');

    // Transfer 5,000,000 VND to safe hospital account 1188999000888 (ACC-HOSP-800)
    await page.locator('#wallet-recipient').fill('1188999000888');
    await page.locator('#wallet-amount').fill('5000000');
    await page.locator('#wallet-msg').fill('Thanh toan hoa don benh vien');
    await page.getByRole('button', { name: /Xác nhận Chuyển 5\.000\.000 ₫/i }).click();

    await expect(page.getByText(/Giao dịch hợp lệ — Cho phép thực hiện/i)).toBeVisible();
    await expect(page.getByTestId('wallet-live-balance')).toContainText('40.000.000');
    await expect(page.getByText(/TXN-WAL-/)).toBeVisible();

    // Switch directly to Merchant Soundbox via integrated button (Case A: Verified Match)
    await page.getByRole('button', { name: /Đối soát ở Loa Tiểu thương/i }).click();
    await expect(page.getByText(/GIAO DỊCH THẬT — ĐÃ NHẬN TIỀN ĐỦ VÀO SỔ CÁI/i)).toBeVisible();

    // Case B: Amount Manipulation preset
    await page.getByRole('button', { name: /Case B: Bill Sửa Số Tiền/i }).click();
    await expect(page.getByText(/CẢNH BÁO BILL SỬA SỐ TIỀN/i)).toBeVisible();

    // Case C: Non-existent Transaction ID preset
    await page.getByRole('button', { name: /Case C: Bill Không Tồn Tại/i }).click();
    await expect(
      page.getByText(/KHÔNG TÌM THẤY GIAO DỊCH — BILL KHÔNG CÓ TRÊN SỔ CÁI/i)
    ).toBeVisible();

    // Case D: Blocked / Non-Settled TXN
    await page.getByRole('button', { name: /Case D: Giao dịch Đã Bị Chặn/i }).click();
    await expect(page.getByText(/GIAO DỊCH ĐÃ BỊ CHẶN – TIỀN KHÔNG VÀO SỔ CÁI/i)).toBeVisible();

    // Case E: Wrong Merchant Recipient
    await page.getByRole('button', { name: /Case E: Sai Tài Khoản Tiểu Thương Nhận/i }).click();
    await expect(
      page.getByText(/KHÔNG KHỚP NGƯỜI NHẬN — BILL CHUYỂN SANG TÀI KHOẢN KHÁC/i)
    ).toBeVisible();

    guard.assertClean();
  });

  test('Scenario 4: Clawback Refund -> Victim Unified Ledger Restoration -> Single-Refund Idempotency', async ({
    page,
  }) => {
    const guard = attachRuntimeHealthGuards(page);

    await page.getByRole('button', { name: /Trung tâm Điều tra/i }).click();
    await page.getByRole('button', { name: /Bước 1: Chạy AI Điều tra/i }).click();
    await expect(
      page.getByRole('button', { name: /Bước 2: Duyệt & Bật Lá chắn/i })
    ).toBeEnabled({ timeout: 25_000 });
    await page.getByRole('button', { name: /Bước 2: Duyệt & Bật Lá chắn/i }).click();

    // Execute 1-Click Clawback on ALT-APP-003 for primary victim's settled TXN-9011 (25,000,000 VND from ACC-MULE-903 -> ACC-USR-103)
    const clawbackBtn = page.getByRole('button', {
      name: /Thu hồi & Hoàn trả GD Đã Hạch toán \(TXN-9011/i,
    });
    await expect(clawbackBtn).toBeVisible();
    await clawbackBtn.click();

    await expect(page.getByText(/Đã Thu hồi & Hoàn 25\.000\.000 ₫ về Ví Nạn nhân/i)).toBeVisible();
    await expect(page.getByText(/GD gốc: TXN-9011/i)).toBeVisible();
    // Single execution guard: Clawback button disappears once executed
    await expect(clawbackBtn).toHaveCount(0);

    // Check Consumer Wallet reflects exact reconciled victim balance (45M + 25M = 70M)
    await page.getByRole('button', { name: /Ví & Lá chắn Người dùng/i }).click();
    await expect(page.getByTestId('wallet-live-balance')).toContainText('70.000.000');

    guard.assertClean();
  });

  test('Scenario 5: Live Sandbox Case Builder Debounced Preview + Accessible Form + Investigation Flow', async ({
    page,
  }) => {
    const guard = attachRuntimeHealthGuards(page);

    await page.getByRole('button', { name: /Nhập Hồ sơ Kiểm thử/i }).click();
    await expect(page.locator('#sandbox-title')).toBeVisible();

    await page.locator('#sandbox-title').fill('Kiem thu E2E Debounce App Fraud');
    await page.locator('#sandbox-amount').fill('32000000');
    await page.locator('#sandbox-recipient-acc').fill('1903777666555');

    // Wait >120ms debounce interval and submit
    await page.waitForTimeout(200);
    await page
      .getByRole('button', { name: /Tạo Hồ sơ, Dựng Đồ thị & Chạy Điều tra Ngay/i })
      .click();

    await expect(
      page.getByRole('button', { name: /Bước 2: Duyệt & Bật Lá chắn/i })
    ).toBeVisible({ timeout: 25_000 });
    guard.assertClean();
  });

  test('Scenario 6: Split-Screen Mode Horizontal Triage Queue + Batch Triage 1-Click Execution', async ({
    page,
  }) => {
    const guard = attachRuntimeHealthGuards(page);

    await page.getByRole('button', { name: /Trung tâm Điều tra/i }).click();
    await page.getByRole('button', { name: /Xem Song song Ví/i }).click();

    // Compact horizontal queue shows Gom nhóm AI
    const gomNhomBtn = page.getByRole('button', { name: /Gom nhóm AI/i });
    await expect(gomNhomBtn).toBeVisible();
    await gomNhomBtn.click();

    const batchBtn = page.getByRole('button', { name: /Thực thi Gom nhóm 1-Chạm/i });
    await expect(batchBtn).toBeVisible();
    await batchBtn.click();

    await expect(page.getByText(/Hoàn tất Xử lý Gom nhóm 1-Chạm/i)).toBeVisible();
    guard.assertClean();
  });

  test('Scenario 7: Compliance Report Print CSS Stylesheet + Accessibility & Mobile Responsive Check', async ({
    page,
  }) => {
    const guard = attachRuntimeHealthGuards(page);

    await page.getByRole('button', { name: /Trung tâm Điều tra/i }).click();
    await page.getByRole('button', { name: /Biên bản PDF/i }).click();

    const dialog = page.getByRole('dialog');
    await expect(dialog).toBeVisible();

    // Emulate print media and verify light-ink print stylesheet & hidden controls
    await page.emulateMedia({ media: 'print' });
    const cardBg = await page
      .locator('.printable-dossier-card')
      .evaluate((el) => getComputedStyle(el).backgroundColor);
    expect(cardBg).toBe('rgb(255, 255, 255)');

    const noPrintDisplay = await page
      .locator('.printable-dossier-card .no-print')
      .first()
      .evaluate((el) => getComputedStyle(el).display);
    expect(noPrintDisplay).toBe('none');

    await page.emulateMedia({ media: 'screen' });
    await page.getByRole('button', { name: /Đóng biên bản/i }).click();

    // Responsive check at 390x844 mobile viewport
    await page.setViewportSize({ width: 390, height: 844 });
    const overflow = await page.evaluate(
      () => document.documentElement.scrollWidth > window.innerWidth + 2
    );
    expect(overflow).toBe(false);

    guard.assertClean();
  });

  test('Scenario 8 (Wave 3): Merchant Vision Intelligence — Upload PNG Receipt, Guard SVG, Separate AI OCR vs Core Ledger & Keep Image Out of LocalStorage', async ({
    page,
  }) => {
    const guard = attachRuntimeHealthGuards(page);

    await page.getByRole('button', { name: /Ví & Lá chắn Người dùng/i }).click();
    await page.getByRole('button', { name: /Tiểu thương \(Bill & Loa\)/i }).click();

    await expect(page.getByText(/AI Vision Quét Ảnh Bill/i)).toBeVisible();

    // 1. Attempt uploading SVG file via file input -> rejected gracefully in UI without crash
    await page.locator('#merch-vision-upload').setInputFiles({
      name: 'malicious.svg',
      mimeType: 'image/svg+xml',
      buffer: Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'),
    });
    await expect(page.getByText(/Chỉ hỗ trợ ảnh chụp màn hình PNG, JPEG hoặc WebP/i)).toBeVisible();

    // 2. Upload valid 1x1 PNG binary (intercept /api/merchant/vision cleanly to test deterministic OCR + Ledger cross-check)
    await page.route('**/api/merchant/vision', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          verification: {
            status: 'AMOUNT_MISMATCH',
            verificationSource: 'AI_OCR_AND_LEDGER',
            extractedFields: {
              claimedTransactionId: 'TXN-MERCH-1K',
              claimedAmountVnd: 15_000_000,
              currency: 'VND',
              claimedRecipientAccount: '1188999000888',
              claimedRecipientName: 'BENH VIEN DA KHOA QUOC TE',
              claimedSenderInfo: null,
              claimedTransactionTime: null,
              paymentProvider: 'MoMo',
              otherReferences: [],
              detectedAmountsCount: 1,
              candidateTransactionIds: ['TXN-MERCH-1K'],
              imageQualityStatus: 'CLEAR',
              fieldConfidence: { transactionId: 0.96, amountVnd: 0.94, recipientAccount: 0.92, overall: 0.94 },
              extractionWarnings: [],
              missingFields: [],
              suspiciousVisualIndicators: [],
            },
            ledgerComparison: {
              foundInLedger: true,
              txId: 'TXN-MERCH-1K',
              ledgerStatus: 'SETTLED',
              actualAmountVnd: 1_000,
              claimedAmountVnd: 15_000_000,
              expectedMerchantAccountId: 'ACC-HOSP-800',
              actualReceiverAccountId: 'ACC-HOSP-800',
              matchedSenderName: 'NGUYEN VAN GIAN',
            },
            matchedFields: ['transactionId', 'recipientAccount', 'ledgerSettled'],
            mismatchedFields: ['amountVnd'],
            reasonsVi: [
              'CẢNH BÁO BILL SỬA SỐ TIỀN (LỆCH SỐ TIỀN THỰC NHẬN)',
              'Ảnh Bill khách đưa ghi 15.000.000 ₫, NHƯNG Sổ cái chỉ ghi nhận 1.000 ₫.',
            ],
            warningsVi: [],
            recommendedNextActionVi: 'GIỮ LẠI HÀNG HÓA • Chụp hình đối chiếu.',
            confidenceNoteVi: 'Ước lượng mô hình AI — Không phải bằng chứng thanh toán.',
            modelUsed: 'gemini-2.5-flash',
            latencyMs: 185,
          },
        }),
      });
    });

    const tinyPngBase64 =
      'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=';
    await page.locator('#merch-vision-upload').setInputFiles({
      name: 'receipt-bill.png',
      mimeType: 'image/png',
      buffer: Buffer.from(tinyPngBase64, 'base64'),
    });

    await expect(page.getByText(/1\. Thông tin AI OCR Trích xuất/i)).toBeVisible();
    await expect(page.getByTestId('merchant-vision-verdict')).toContainText('AMOUNT_MISMATCH');
    await expect(page.getByTestId('merchant-vision-verdict')).toContainText('CẢNH BÁO BILL SỬA SỐ TIỀN');

    // Ensure raw image base64 was NOT written into localStorage
    const storedDeltaStr = await page.evaluate(
      () => localStorage.getItem('aegisops_session_delta_v1') || ''
    );
    expect(storedDeltaStr).not.toContain(tinyPngBase64);

    guard.assertClean();
  });

  test('Scenario 9 (Wave 3): Adaptive HITL Feedback Lifecycle — Create, Scope/Explainability Display & L2 Revocation', async ({
    page,
  }) => {
    const guard = attachRuntimeHealthGuards(page);

    await page.getByRole('button', { name: /Trung tâm Điều tra/i }).click();
    // Open ALT-FPR-004 (Hospital Safe False Positive case)
    await page.getByRole('button', { name: /Vụ #4 \(ALT-FPR-004\)/i }).click();

    // Open Adaptive HITL Feedback drawer
    await page.getByRole('button', { name: /Bộ nhớ Phản hồi HITL/i }).click();
    await page.locator('#hitl-scope-select').selectOption('RECIPIENT_PATTERN');
    await page.locator('#hitl-rationale-input').fill('E2E Xac nhan benh vien doi tac an toan');
    await page.getByRole('button', { name: /Lưu Bộ nhớ HITL An toàn/i }).click();

    await expect(page.getByText(/APPROVED_ACTIVE/)).toBeVisible();
    await expect(page.getByText(/Adaptive HITL Memory: Điểm gốc/i)).toBeVisible();
    await expect(page.getByText(/Adaptive HITL SAFE/i)).toBeVisible();

    // Revoke active HITL memory -> changes status cleanly to REVOKED & removes active adjustment badge
    await page.getByRole('button', { name: /Thu hồi \(Revoke\)/i }).click();
    await expect(page.getByText('REVOKED', { exact: true })).toBeVisible();
    await expect(page.getByText(/Adaptive HITL SAFE/i)).toHaveCount(0);

    guard.assertClean();
  });

  test('Scenario 10 (CR-1): Cross-Session /api/workspace Isolation, Server-Side /api/merchant/verify & Honest Initial Dashboard KPIs', async ({
    page,
    request,
  }) => {
    const guard = attachRuntimeHealthGuards(page);

    // 1. Honest initial Dashboard KPIs (zero fabricated 6.4s or +1 benign offset)
    await expect(page.getByTestId('kpi-avg-latency')).toContainText('Chưa có dữ liệu');
    await expect(page.getByTestId('kpi-benign-alerts')).toContainText('0 cảnh báo');
    await expect(page.getByText(/6\.4 giây/i)).toHaveCount(0);

    // 2. Unauthenticated GET/POST /api/workspace via clean APIRequestContext -> HTTP 401
    const unauthGet = await request.get('/api/workspace', {
      headers: { 'x-workspace-session': 'forged-victim-session' },
    });
    expect(unauthGet.status()).toBe(401);

    const unauthPost = await request.post('/api/workspace', {
      headers: { 'x-workspace-session': 'forged-victim-session' },
      data: {},
    });
    expect(unauthPost.status()).toBe(401);

    // 3. Authenticated browser context cookie jar (`page.request`) accesses own session (200),
    //    but attempting to read or mutate another session via header/body is rejected (401 / 403)
    const ownAuthedGet = await page.request.get('/api/workspace');
    expect(ownAuthedGet.status()).toBe(200);

    const crossHeaderGet = await page.request.get('/api/workspace', {
      headers: { 'x-workspace-session': 'other-user-victim-session' },
    });
    expect(crossHeaderGet.status()).toBe(401);

    const crossBodyPost = await page.request.post('/api/workspace', {
      data: { clientDelta: { sessionId: 'other-user-victim-session' } },
    });
    expect(crossBodyPost.status()).toBe(403);

    // 4. Merchant manual verification MUST call server POST /api/merchant/verify
    await page.getByRole('button', { name: /Ví & Lá chắn Người dùng/i }).click();
    await page.getByRole('button', { name: /Tiểu thương \(Bill & Loa\)/i }).click();

    const verifyResponsePromise = page.waitForResponse(
      (res) => res.url().includes('/api/merchant/verify') && res.request().method() === 'POST'
    );
    await page.getByRole('button', { name: /Case B: Bill Sửa Số Tiền/i }).click();
    const verifyRes = await verifyResponsePromise;
    expect(verifyRes.status()).toBe(200);
    await expect(page.getByText(/CẢNH BÁO BILL SỬA SỐ TIỀN/i)).toBeVisible();

    guard.assertClean();
  });

  test('Scenario 11 (CR-2): AI Source Provenance Badge, Circular 77 CERTIFICATION_NOT_VERIFIED Disclosure & Cooling-Off HELD Balance Protection', async ({
    page,
  }) => {
    const guard = attachRuntimeHealthGuards(page);

    // 1. Investigation panel clearly distinguishes Deterministic vs Live AI source provenance
    await page.getByRole('button', { name: /Trung tâm Điều tra/i }).click();
    await expect(page.getByTestId('ai-source-badge')).toContainText(/Tóm tắt Định lượng/i);

    // 2. Compliance Report Modal transparently surfaces Law 91/2025, Decree 356/2025, Circular 50/2024 amended by 77/2025, CERTIFICATION_NOT_VERIFIED & SIMULATED disclosures
    await page.getByRole('button', { name: /Biên bản PDF/i }).click();
    const dialog = page.getByRole('dialog');
    await expect(dialog).toBeVisible();
    await expect(dialog).toContainText('CERTIFICATION_NOT_VERIFIED');
    await expect(dialog).toContainText(/91\/2025\/QH15/i);
    await expect(dialog).toContainText(/356\/2025\/NĐ-CP/i);
    await expect(dialog).toContainText(/LEGAL_REVIEW_REQUIRED/i);
    await expect(dialog).toContainText(/SIMULATED/i);
    await expect(dialog).not.toContainText(/0% Hallucination/i);
    await page.getByRole('button', { name: /Đóng biên bản/i }).click();

    // 3. Consumer Wallet WARN_COOLING_OFF (scam note before L2 Shield) holds transfer (HELD) without prematurely deducting balance!
    await page.getByRole('button', { name: /Ví & Lá chắn Người dùng/i }).click();
    await expect(page.getByTestId('wallet-live-balance')).toContainText('45.000.000');
    await page.getByRole('button', { name: /Xác nhận Chuyển/i }).click();
    await expect(page.getByText(/CẢNH BÁO LÀM NGUỘI TÂM LÝ/i)).toBeVisible();
    await expect(page.getByTestId('wallet-live-balance')).toContainText('45.000.000');

    guard.assertClean();
  });
});
