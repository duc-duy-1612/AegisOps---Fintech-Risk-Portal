# AegisOps — AI-Powered Fintech Fraud, Cyber Defense & Real-Time User Protection Workspace

**Cuộc thi:** MoMo Tech Contest — *Imagine the Future Workspace (Human Centered. AI Powered)*  
**Chủ đề đăng ký:** Kết hợp cả 3 chủ đề (**Trợ lý AI** + **An ninh mạng** + **Chống lừa đảo**)  
**Đối tượng người dùng:** Đội ngũ Vận hành Rủi ro, Chống gian lận & An ninh mạng Fintech (Risk/Fraud/SecOps L1/L2) và Người dùng cuối trên ứng dụng Ví điện tử.

---

## 1. Tuyên ngôn Giá trị & Điểm khác biệt Cốt lõi

- **Vấn đề:** Đội ngũ vận hành Fintech hiện mất **20–40 phút** tra cứu thủ công trên 6–7 màn hình rời rạc để xác minh 1 cảnh báo gian lận hoặc khiếu nại lừa đảo. Trong thời gian đó, tiền đã bị tẩu tán qua mạng lưới tài khoản rác (*Mule Rings*) hoặc rút cạn qua lỗ hổng *Race Condition*. Ngược lại, nếu khóa tự động bằng rule cứng nhắc sẽ dẫn đến **khóa oan khách hàng thật**.
- **Giải pháp AegisOps (Nền tảng SaaS Vòng khép kín từ Điều tra đến Lá chắn Mô phỏng):**
  1. **App Shell Thương mại 5 Phân hệ (Menu Dọc, Tag Box Lọc, Dashboard Tổng quan):** Trang chủ mở ra **Dashboard Tổng quan** với KPI trực quan, biểu đồ phân bổ rủi ro, bảng danh sách vụ việc có Tag Box lọc & tìm kiếm nhanh, cùng tính năng **Nhập/Xuất hàng loạt CSV & JSON**.
  2. **5 Công cụ Truy vết Định lượng (Deterministic Forensics Engine — Quyết định gốc) & Biểu mẫu Hồ sơ 4 Phần:** Tự động phân tích độ lệch Z-Score, truy vết đồ thị BFS & cụm thiết bị dùng chung (*Mule Ring / Smurfing*), kiểm tra log phiên chiếm đoạt tài khoản (*Persistent ATO*), phát hiện xung đột đồng thời (*Race Condition TOCTOU / Webhook HMAC*), hỗ trợ người dùng nhập dữ liệu kiểm thử qua **Biểu mẫu 4 Phần** tính điểm động tức thời.
  3. **Trợ lý Điều tra Đa phương thức (Gemini 3.5 Flash-Lite / Fallback 2.5 Flash-Lite) & Kiểm soát Kép Maker–Checker (L1/L2):** Hỗ trợ đọc ảnh chụp màn hình bằng chứng (Vision OCR), kiểm định tham chiếu mã trích dẫn qua `Citation Validator` (cần chuyên viên rà soát ngữ nghĩa), phân quyền Ngân hàng **L1 Maker đề xuất → L2 Checker phê duyệt**, và xuất **Biên bản Đối chiếu Pháp lý (QĐ 2345, TT 50/2024 sửa đổi bởi TT 77/2025, Luật 91/2025/QH15 & NĐ 356/2025/NĐ-CP; SIMO mô phỏng)**.
  4. **Lá chắn Ví Cá nhân Mô phỏng, Bảo vệ Tiểu thương & Thu hồi GD Đã Hạch toán:** Ngay khi L2 duyệt Playbook, hệ thống phong tỏa tài khoản Mule trong phiên mô phỏng, cho phép **1-Click Clawback đảo sổ giao dịch đã hạch toán (SETTLED/COMPLETED)** về ví nạn nhân, kích hoạt **Đèn Tín nhiệm 3 Màu (mô phỏng)**, giải mã **VietQR EMVCo cục bộ**, **Phân tích Link Phishing / .APK**, **Thẻ Gỡ bùa Tâm lý**, và tích hợp chế độ **Tiểu thương (Loa Soundbox Web Speech & Đối soát Bill Chuyển khoản Giả)** với Sổ cái Hợp nhất cục bộ.

---

## 2. Hướng dẫn Chạy Dự án (Local & Production)

### Yêu cầu Môi trường
- **Node.js:** `24.x LTS` (`>=24.0.0 <25.0.0`)
- **npm:** `>= 10.x`

### Các bước Khởi chạy
1. **Lấy mã nguồn (clone từ kho lưu trữ hoặc tải gói mã nguồn từ trang dự án) và cài đặt thư viện:**
   ```bash
   npm install
   ```
2. **Cấu hình biến môi trường:**
   Sao chép file `.env.example` thành `.env.local` và điền `GEMINI_API_KEY` (Google AI Studio) cho chạy cục bộ:
   ```env
   GEMINI_API_KEY=your_gemini_api_key_here
   GEMINI_PRIMARY_MODEL=gemini-3.5-flash-lite
   GEMINI_FALLBACK_MODEL=gemini-2.5-flash-lite
   AI_RATE_LIMIT_PER_MIN=30
   ```
   *(Lưu ý: Hệ thống sử dụng chuỗi dự phòng 3 tầng `gemini-3.5-flash-lite` → `gemini-2.5-flash-lite` → `Deterministic Forensics Engine`, đảm bảo chuyển sang chế độ dự phòng định lượng an toàn khi hết quota hoặc lỗi kết nối API. Xem cấu hình biến môi trường mở rộng cho staging/production — gồm PostgreSQL TLS, Upstash Redis, các khóa bí mật tách miền và quy trình triển khai chưa kiểm chứng trực tiếp trên hạ tầng đám mây — tại [docs/DEPLOYMENT_RUNBOOK.md](docs/DEPLOYMENT_RUNBOOK.md)).*
3. **Chạy môi trường phát triển (Development):**
   ```bash
   npm run dev
   ```
   Truy cập: `http://localhost:3000`
4. **Kiểm thử tự động (Unit & Red-Team Tests + TypeScript Check + Production Build):**
   ```bash
   npm test
   npm run typecheck
   npm run build
   npm start
   ```

---

## 3. Hướng dẫn Dùng thử Nhanh cho Ban Giám Khảo (3-Step Golden Path)

1. **Bước 1 — Chạy AI Điều tra:** Mở ứng dụng (mặc định chọn sẵn **Vụ #1 `ALT-APP-003` — Lừa đảo giả danh Công an gửi ảnh lệnh bắt giữ**), bấm nút màu tím **"Bước 1: Chạy AI Điều tra"** ở cột phải. Quan sát thanh tiến trình quét 5 bước, huy hiệu nguồn phân tích (`ai-source-badge`) và kết quả tổng hợp.
2. **Bước 2 — Kiểm tra Bằng chứng & Duyệt Playbook 1-Click:** Bấm vào các mã bằng chứng (`EVD-103`, `TXN-9011`, `DEV-EMU-666`) để xem dữ liệu gốc hoặc phóng to bức ảnh đoạn chat lừa đảo. Sau đó bấm nút màu vàng **"Bước 2: Duyệt & Bật Lá chắn (1-Click)"**.
3. **Bước 3 — Kiểm chứng Chặn Giao dịch trên Ví Người dùng:** Bấm nút màu xanh lá **"Bước 3: Mở Ví Kiểm chứng Chặn Ngay"** → Bấm **"Xác nhận Chuyển"** tới số tài khoản `1903999888777` để kiểm chứng **Lá chắn Aegis Shield chặn giao dịch lừa đảo (trạng thái `BLOCKED`, số dư 45.000.000 ₫ giữ nguyên)**. Xem kịch bản demo đầy đủ trong [docs/DEMO_VIDEO_3MIN_SCRIPT.md](docs/DEMO_VIDEO_3MIN_SCRIPT.md).
4. **Thử nghiệm các Kịch bản Khác & Live Sandbox:**
   - Chọn **Vụ #2 (`ALT-ATO-001`)**: Truy vết chiếm đoạt phiên đăng nhập sau khi đổi mật khẩu & chia nhỏ 48 triệu qua 3 tài khoản Mule.
   - Chọn **Vụ #3 (`ALT-BLG-002`)**: Phát hiện tấn công *Race Condition (12 request/140ms)* nhân bản voucher & giả mạo chữ ký Webhook HMAC.
   - Chọn **Vụ #4 (`ALT-FPR-004`)**: Trợ lý AI nhận diện giao dịch đóng viện phí cấp cứu ban đêm hợp lệ trên iPhone mới, khuyến nghị **Không khóa oan khách hàng** (*Human-Centered AI*).
   - Bấm **"+ Tự tạo Vụ việc Mới (Live Sandbox)"**: Tự dán đoạn tin nhắn lừa đảo hoặc tải ảnh chụp màn hình bất kỳ từ máy tính của Ban giám khảo để AI bóc tách số tài khoản, dựng đồ thị động và chặn trực tiếp trên Ví mô phỏng.

---

## 4. Kiến trúc Công nghệ (Clean Architecture 4 Lớp)

- **`src/domain/` (Pure Domain & Deterministic Forensics):**
  - `types.ts`: Toàn bộ thực thể nghiệp vụ (`StandardCaseInputSpec`, `OperatorRole`, `WorkspaceNotification`) và Zod schemas.
  - `forensics-analyzers.ts`: 5 công cụ truy vết định lượng thuần TypeScript (`analyzeAccountProfile`, `analyzeMuleGraph`, `inspectCyberSession`, `detectBusinessLogicAbuse`, `correlateScamCampaign`) cùng bộ tính Z-Score, Smurfing Entropy, Bipartite Clustering và SHAP-like Risk Attribution.
  - `batch-io.ts`: Bộ phân tích & xuất dữ liệu hàng loạt CSV (UTF-8 BOM) / JSON chuẩn RFC-4180.
  - `campaign-correlator.ts`: Bộ gom nhóm chiến dịch đa vụ án (`Batch Triage`) phát hiện băng nhóm chung thiết bị.
  - `vietqr-inspector.ts`: Giải mã chuỗi EMVCo VietQR & kiểm tra khớp tên pháp lý NAPAS.
  - `sandbox-synthesizer.ts`: Tổng hợp đồ thị động, trích xuất thực thể và chấm điểm tức thời cho **Biểu mẫu 4 Phần** & Live Sandbox.
  - `shield-evaluator.ts`: Động cơ đánh giá và chặn giao dịch thời gian thực trên Ví người dùng cuối + Đèn Độ tin cậy 3 Màu chuẩn MoMo/A05/SIMO.
  - `compliance-report.ts`: Bộ khởi tạo Biên bản Điều tra & Đối chiếu Pháp lý QĐ 2345 / TT 50/2024 (sửa đổi bởi TT 77/2025) / Luật 91/2025/QH15 & NĐ 356/2025/NĐ-CP / SIMO mô phỏng.
- **`src/application/` (Orchestration & Guardrails):**
  - `citation-validator.ts`: Bộ kiểm định tham chiếu mã bằng chứng (`validateAndRepairCitations`), loại bỏ mã bằng chứng không tồn tại khỏi chip trích dẫn (chuyên viên vẫn rà soát ngữ nghĩa nội dung).
  - `workspace-orchestrator.ts`: Điều phối luồng điều tra, **kiểm soát kép Maker–Checker L1/L2**, nhập dữ liệu hàng loạt CSV/JSON, hỏi đáp Copilot và mô phỏng Ví.
- **`src/infrastructure/` (Adapters & Security):**
  - `gemini-agent.ts`: Kết nối Google Gemini Multimodal API với chuỗi dự phòng 3 tầng.
  - `workspace-store.ts`: Lưu trữ cô lập theo phiên giám khảo (`x-workspace-session`) kết hợp đồng bộ `SessionDeltaSnapshot` chống mất trạng thái trên môi trường Serverless.
  - `security-guard.ts` & `api-schemas.ts`: Giới hạn tần suất gọi API (Rate Limiter), kiểm tra định dạng/giới hạn payload ảnh tải lên (nhị phân ảnh gốc tối đa `3,000,000` bytes / `3.0 MB` thập phân, chuỗi base64 data URL tối đa `4,000,064` ký tự, toàn bộ thân yêu cầu JSON tối đa `4,194,304` bytes / `4 MiB`) và lọc ký tự chống XSS.
  - `seed-scenarios.ts`: Bộ dữ liệu mô phỏng thực chiến cho 4 kịch bản Fintech.
- **`src/presentation/` & `src/app/` (Next.js 15 App Router & OLED Dark UI):**
  - Giao diện trung tâm chỉ huy 3 cột, đồ thị tương tác `@xyflow/react`, cửa sổ mô phỏng Ví điện tử và xuất biên bản PDF.

---

## 5. Minh bạch Tài sản có sẵn, Thư viện Mã nguồn mở & Công cụ AI đã dùng

### 5.1. Tài sản có sẵn (Pre-existing Assets)
- **Không sử dụng mã nguồn sản phẩm có sẵn:** Toàn bộ mã nguồn ứng dụng (`src/`), bộ công cụ Deterministic Forensics, bộ dữ liệu mô phỏng 4 kịch bản (`seed-scenarios.ts`), ảnh minh họa SVG và bộ kiểm thử (`tests/`) được xây dựng mới 100% trong khuôn khổ cuộc thi.
- **Tri thức chuyên môn tham khảo:** Các chuẩn mực và tài liệu tham khảo về kiểm thử bảo mật web/API (OWASP WSTG, phân loại lỗ hổng ATO/Session/Business Logic) và kiến trúc phần mềm đã được sử dụng làm tài liệu định hướng trong quá trình phát triển và không được đóng gói trong kho mã nguồn công khai này.

### 5.2. Danh sách Thư viện Mã nguồn mở Trực tiếp (`package.json` — 9 Production + 12 Development)

#### Thư viện Production Trực tiếp (9)
| Thư viện | Dải phiên bản (`package.json`) | Phiên bản khóa (`package-lock.json`) | Giấy phép khai báo | Mục đích sử dụng |
| :--- | :--- | :--- | :--- | :--- |
| `@xyflow/react` | `^12.4.2` | `12.12.1` | MIT | Vẽ đồ thị tương tác truy vết dòng tiền & thiết bị liên kết |
| `clsx` | `^2.1.1` | `2.1.1` | MIT | Ghép lớp CSS có điều kiện cho thành phần giao diện |
| `lucide-react` | `^0.475.0` | `0.475.0` | ISC | Bộ biểu tượng SVG chuẩn giao diện |
| `next` | `15.5.29` | `15.5.29` | MIT | Fullstack React Framework & App Router API Routes |
| `pg` | `^8.23.1` | `8.23.1` | MIT | Trình điều khiển PostgreSQL (Neon TLS `verify-full` & channel binding) |
| `react` | `^19.0.0` | `19.3.1` | MIT | Thư viện xây dựng giao diện người dùng |
| `react-dom` | `^19.0.0` | `19.3.1` | MIT | Kết xuất React DOM phía client/server |
| `tailwind-merge` | `^3.0.1` | `3.7.1` | MIT | Hợp nhất lớp tiện ích Tailwind CSS không xung đột |
| `zod` | `^4.6.7` | `4.6.7` | MIT | Kiểm tra schema đầu vào API & ép kiểu Structured Output cho AI |

#### Thư viện Development Trực tiếp (12)
| Thư viện | Dải phiên bản (`package.json`) | Phiên bản khóa (`package-lock.json`) | Giấy phép khai báo | Mục đích sử dụng |
| :--- | :--- | :--- | :--- | :--- |
| `@playwright/test` | `^1.65.1` | `1.65.1` | Apache-2.0 | Kiểm thử E2E trình duyệt Chromium cô lập |
| `@types/node` | `^22.13.4` | `22.20.5` | MIT | Định nghĩa kiểu TypeScript cho Node.js |
| `@types/pg` | `^8.23.1` | `8.23.1` | MIT | Định nghĩa kiểu TypeScript cho `pg` |
| `@types/react` | `^19.0.8` | `19.3.0` | MIT | Định nghĩa kiểu TypeScript cho React |
| `@types/react-dom` | `^19.0.3` | `19.3.0` | MIT | Định nghĩa kiểu TypeScript cho React DOM |
| `autoprefixer` | `^10.4.20` | `10.7.0` | MIT | Tự động thêm tiền tố CSS trình duyệt cho PostCSS |
| `eslint` | `^8.57.1` | `8.57.1` | MIT | Kiểm tra chất lượng và quy tắc mã nguồn tĩnh |
| `eslint-config-next` | `15.5.29` | `15.5.29` | MIT | Cấu hình ESLint chuẩn cho Next.js |
| `postcss` | `^8.5.33` | `8.5.33` | MIT | Xử lý đường ống CSS cho Tailwind CSS |
| `tailwindcss` | `^3.4.17` | `3.4.19` | MIT | Hệ thống thiết kế giao diện OLED Dark Mode |
| `typescript` | `^5.7.3` | `5.9.3` | Apache-2.0 | Kiểm tra kiểu tĩnh nghiêm ngặt (`strict: true`) |
| `vitest` | `^4.1.12` | `4.1.12` | MIT | Kiểm thử tự động Unit Test & Red-Team Test |

### 5.3. Công cụ AI đã sử dụng (AI Tools Disclosure)
1. **Thành phần AI cốt lõi bên trong sản phẩm (Runtime Core AI):**
   - **Google Gemini API (`gemini-3.5-flash-lite` mặc định & `gemini-2.5-flash-lite` dự phòng):** Hỗ trợ phân tích bằng chứng đa phương thức (đọc ảnh chụp màn hình đoạn chat lừa đảo / hóa đơn tiểu thương), bóc tách thực thể trong Live Sandbox, tóm tắt kết quả từ 5 công cụ Forensics và trả lời hỏi đáp của chuyên viên vận hành (quyết định rủi ro gốc luôn do công cụ định lượng nắm giữ).
2. **Công cụ AI hỗ trợ phát triển (Development Assistant):**
   - **Google Antigravity IDE Agent:** Hỗ trợ thiết kế kiến trúc Clean Architecture, viết mã nguồn TypeScript, kiểm thử tự động và biên soạn tài liệu kỹ thuật dưới sự chỉ đạo và kiểm duyệt của đội thi.

---

## License & Usage

- **Public Portfolio Viewing:** This repository is publicly available for viewing and technical evaluation as a portfolio project.
- **No Open-Source License Grant:** No open-source license is granted by the AegisOps project owner (`"license": "UNLICENSED"` in `package.json`). No additional project-level permission to use, modify, redistribute, or commercially reuse AegisOps-owned code is granted by this repository.
- **GitHub Platform Terms:** Public repository viewing and forking within GitHub remain governed by GitHub's Terms of Service.
- **Applicable Law:** Any rights available under applicable law remain unaffected.
- **Third-Party Dependencies & Assets:** Third-party packages, fonts, and external assets remain independent from the AegisOps project license status and are governed by their respective licenses and terms.
