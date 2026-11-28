# AegisOps — AI-Powered Fintech Fraud, Cyber Defense & Real-Time User Protection Workspace

> **Môi trường Dự thi Công khai (Synthetic-Data-Only Contest Edition):**  
> - **Bản triển khai trực tuyến (Live Demo):** `https://aegisops-momo-contest-2026.netlify.app`  
> - **Cuộc thi:** MoMo Tech Contest 2026 — *Imagine the Future Workspace (Human Centered. AI Powered)*  
> - **Chủ đề tích hợp:** **Trợ lý AI** + **An ninh mạng** + **Chống lừa đảo**  
> - **Đối tượng phục vụ:** Đội ngũ Vận hành Rủi ro, Chống gian lận & An ninh mạng Fintech (*Risk / Fraud / SecOps L1–L2*), Người dùng cuối trên ứng dụng Ví điện tử và Tiểu thương (*Merchants*).  
> - **Lưu ý bảo mật dữ liệu:** Toàn bộ hồ sơ, giao dịch, số tài khoản và ảnh chứng cứ trong phiên bản dự thi đều là **dữ liệu mô phỏng tổng hợp (synthetic data)** — không nhập CCCD, số điện thoại, số tài khoản hay hóa đơn ngân hàng thật.

---

## 1. Giới thiệu Tổng quan (Project Overview)

**AegisOps** là nền tảng không gian làm việc điều tra gian lận và bảo vệ người dùng theo thời gian thực dành cho hệ sinh thái ví điện tử Fintech. Thay vì để chuyên viên rủi ro phải chuyển đổi rời rạc giữa nhiều màn hình tra cứu log, bảng giao dịch, hệ thống chặn tài khoản và công cụ soạn hồ sơ pháp lý, AegisOps hợp nhất toàn bộ quy trình thành một **vòng phòng vệ khép kín 4 tầng (Closed-Loop Defense Workspace)**:

```text
[1] Dữ liệu Đầu vào & Telemetry (Giao dịch, Ảnh chat OCR, VietQR EMVCo, Phiên đăng nhập, API/Webhook)
        ↓
[2] 5 Công cụ Truy vết Định lượng (Deterministic Forensics Engine — Nắm quyền quyết định rủi ro gốc)
        ↓
[3] Trợ lý AI Đa phương thức Gemini + Citation Validator (Giải thích tiếng Việt, hỏi đáp & chống ảo giác)
        ↓
[4] Phê duyệt Kép L1/L2 (Maker–Checker) → Lá chắn Ví Mô phỏng, Thu hồi Clawback & Hồ sơ Pháp lý NHNN/SIMO
```

---

## 2. Bối cảnh & Bài toán Thực tiễn

Trong vận hành thanh toán số và ví điện tử hiện đại tại Việt Nam, các đội ngũ Risk/Fraud/SecOps đang đối mặt đồng thời với **4 thách thức cốt lõi**:

1. **Tốc độ tẩu tán tiền nhanh hơn tốc độ điều tra thủ công:** Một vụ lừa đảo thao túng tâm lý (*APP Fraud* — giả danh công an, shipper, cơ quan chức năng) hoặc chiếm đoạt phiên (*Account Takeover — ATO*) chỉ mất vài phút để chia nhỏ dòng tiền (*Smurfing*) qua mạng lưới tài khoản rác (*Mule Rings*), trong khi quy trình tra cứu thủ công trên 6–7 màn hình thường kéo dài **20–40 phút**.
2. **Xung đột giữa "chặn chặt" và "tránh khóa oan" (*False Positive*):** Luật cứng (*static rules*) dễ khóa nhầm các giao dịch khẩn cấp hợp lệ của khách hàng thật (ví dụ: đóng viện phí cấp cứu lúc nửa đêm trên thiết bị mới), gây tổn hại trực tiếp đến trải nghiệm và niềm tin người dùng.
3. **Rủi ro từ AI tạo sinh thuần túy (*AI Hallucination & Prompt Injection*):** Nếu giao trực tiếp quyền quyết định khóa tài khoản cho LLM, kẻ tấn công có thể chèn câu lệnh độc hại vào nội dung chuyển khoản hoặc ảnh hóa đơn giả để đánh lừa AI bỏ qua gian lận hoặc suy diễn sai bằng chứng.
4. **Áp lực tuân thủ quy định pháp lý ngày càng chặt chẽ:** Các tổ chức thanh toán phải đáp ứng yêu cầu xác thực sinh trắc học theo ngưỡng giao dịch (**QĐ 2345/QĐ-NHNN**), an toàn bảo mật dịch vụ trực tuyến (**TT 50/2024/TT-NHNN**, sửa đổi bổ sung bởi **TT 77/2025/TT-NHNN**), bảo vệ dữ liệu cá nhân (**Luật 91/2025/QH15 & NĐ 356/2025/NĐ-CP**) và chuẩn hóa hồ sơ báo cáo gian lận (**SIMO**).

---

## 3. Mô tả Chi tiết Sản phẩm (Product Description)

AegisOps được thiết kế theo mô hình **App Shell 5 phân hệ chuyên biệt**, tối ưu cho cả màn hình chỉ huy Desktop/Laptop lẫn Tablet/Mobile:

### 3.1. Năm Phân hệ Vận hành Cốt lõi
1. **Dashboard Tổng quan (`Overview Dashboard`):**
   - Hiển thị thanh hướng dẫn 3 bước cho người mới, 4 chỉ số KPI đo lường thực tế (giá trị giao dịch đã chặn & thu hồi, độ trễ điều tra AI trung bình, số lá chắn đang hoạt động & vụ việc chờ duyệt, số cảnh báo hợp lệ được giải tỏa tránh khóa oan).
   - Bảng **Danh sách Vụ việc Cần Xử lý** hợp nhất kèm thanh điểm rủi ro trực quan, bộ lọc phân loại kịch bản, tìm kiếm nhanh (`Ctrl + K`), chế độ **Live Feed**, và **Nhập/Xuất hàng loạt CSV & JSON**.
   - Bảng đối chiếu **Shadow Mode (Rule cũ vs. AegisOps AI)** và sơ đồ **Kiến trúc 4 Tầng** giúp giám khảo nhìn rõ giá trị khác biệt.
2. **Trung tâm Điều tra (`Investigation Center`):**
   - **Đồ thị truy vết dòng tiền & cụm thiết bị (`@xyflow/react`):** Trực quan hóa mạng lưới nạn nhân → tài khoản trung gian (*Mule*) → thiết bị giả lập / IP dùng chung, hỗ trợ gom nhóm chiến dịch (*Batch Triage*).
   - **5 Công cụ Truy vết Định lượng (Deterministic Forensics Engine):** Tự động tính độ lệch chuẩn **Z-Score**, truy vết **BFS Mule Ring**, **Smurfing Entropy**, **Bipartite Device Clustering**, phát hiện **Persistent ATO Session Hijack**, và bắt lỗi **Race Condition (TOCTOU) / Webhook HMAC**.
   - **Trợ lý Điều tra AI & Hỏi đáp Copilot:** Tóm tắt bằng chứng đa phương thức có cấu trúc, gắn huy hiệu nguồn phân tích (`PRIMARY_MODEL`, `FALLBACK_MODEL`, hoặc `DETERMINISTIC_FALLBACK`), kiểm định mã trích dẫn qua `Citation Validator`, hỗ trợ **Adaptive HITL Feedback** và phân quyền ngân hàng **L1 Maker đề xuất → L2 Checker phê duyệt**.
3. **Nhập Hồ sơ Kiểm thử (`Case Builder & Live Sandbox`):**
   - Cho phép chuyên viên hoặc Ban Giám Khảo tự nhập kịch bản giao dịch thực tế qua **Biểu mẫu Chuẩn 4 Phần** (Chủ tài khoản, Giao dịch & Dòng tiền, Phiên đăng nhập & Thiết bị, Bằng chứng Chat/Link/OCR) hoặc dán nội dung tin nhắn / tải ảnh chụp mẫu để hệ thống bóc tách thực thể, tính điểm định lượng tức thời và dựng đồ thị điều tra động.
4. **Ví & Lá chắn Người dùng + Tiểu thương (`Wallet Shield & Merchant Protection`):**
   - **Lá chắn Ví Cá nhân (Mô phỏng):** Ngay khi L2 phê duyệt Playbook, tài khoản Mule bị đưa vào danh sách chặn theo phiên; khi người dùng thử chuyển tiền, **Đèn Tín nhiệm 3 Màu** và **Thẻ Gỡ bùa Tâm lý** kích hoạt tức thời để chặn giao dịch (`BLOCKED`) hoặc tạm giữ giải nhiệt (`HELD`), bảo toàn số dư gốc; hỗ trợ **1-Click Clawback** đảo sổ giao dịch đã hạch toán (`SETTLED/COMPLETED`) về ví nạn nhân trên sổ cái hợp nhất cục bộ.
   - **Công cụ An toàn Giao dịch:** Giải mã **VietQR EMVCo cục bộ** đối chiếu tên người nhận, phân tích **Link Phishing / tệp `.APK` giả mạo**.
   - **Chế độ Tiểu thương (Merchant Vision & Soundbox):** Hỗ trợ tải ảnh chụp hóa đơn chuyển khoản (*Vision OCR*) kết hợp **đối soát tách bạch với Sổ cái gốc** (AI OCR không bao giờ có quyền ghi đè số dư hay xác nhận tiền vào nếu sổ cái chưa ghi nhận) và phát âm thanh thông báo **Loa Soundbox** qua Web Speech API.
5. **Pháp lý & Nhật ký Audit (`Compliance & Audit Workspace`):**
   - Khởi tạo **Hồ sơ Pháp lý NHNN** có cấu trúc (hỗ trợ mở xem & in/xuất PDF), tự động ánh xạ đối chiếu **QĐ 2345/QĐ-NHNN**, **TT 50/2024 sửa đổi bởi TT 77/2025**, **Luật 91/2025/QH15 & NĐ 356/2025/NĐ-CP** với trạng thái trung thực (`REQUIREMENT_MAPPED`, `CERTIFICATION_NOT_VERIFIED`, `LEGAL_REVIEW_REQUIRED`, `VERIFIED`).
   - Tạo **Bản tin Đồng bộ SIMO mô phỏng** áp dụng giả danh hóa khóa HMAC-SHA-256 phía máy chủ và lưu vết **Nhật ký Kiểm toán (Audit Trail)** lọc theo tác nhân (*AI Agent*, *Chuyên viên*, *Lá chắn Ví*).

---

## 4. Ý nghĩa Thực tiễn & Tác động (Project Significance & Value)

AegisOps không dừng ở một giao diện chatbot AI minh họa, mà giải quyết trực diện **3 tầng giá trị bền vững**:

### 4.1. Ý nghĩa đối với Đội ngũ Vận hành (*Human-Centered Future Workspace*)
- **Tăng tốc điều tra từ hàng chục phút xuống còn vài giây:** Tự động hóa khâu tổng hợp bằng chứng, tính toán chỉ số định lượng và dựng đồ thị dòng tiền giúp chuyên viên tập trung vào phán đoán nghiệp vụ thay vì ghép nối log thủ công.
- **Giữ con người làm trung tâm quyền quyết định (*Human-in-the-Loop*):** Cơ chế **Maker–Checker (L1/L2)**, bằng chứng trích dẫn đối chiếu được và phản hồi HITL có kiểm soát đảm bảo AI là công cụ khuếch đại năng lực chuyên viên, không phải "hộp đen" tự ý khóa tài khoản.
- **Bảo vệ trải nghiệm khách hàng trung thực:** Kịch bản `ALT-FPR-004` chứng minh khả năng phân biệt giao dịch hợp lệ bất thường (đóng viện phí ban đêm trên máy mới) với tấn công chiếm đoạt, giảm tổn thất uy tín do khóa nhầm.

### 4.2. Ý nghĩa đối với Người dùng Cuối & Cộng đồng Xã hội (*Proactive Anti-Scam*)
- **Chuyển từ "xử lý hậu quả" sang "chặn ngay trước khi mất tiền":** Khi một tài khoản rác bị phát hiện ở bất kỳ vụ việc nào, Lá chắn Ví lập tức ngăn chặn các nạn nhân kế tiếp chuyển tiền vào cùng số tài khoản đó, kết hợp thẻ cảnh báo tâm lý giúp nạn nhân kịp tỉnh táo trước kịch bản giả danh công an/shipper.
- **Bảo vệ tiểu thương khỏi nạn bill chuyển khoản giả:** Tách bạch hoàn toàn giữa đọc ảnh chụp hóa đơn bằng AI Vision với trạng thái hạch toán của sổ cái gốc giúp tiểu thương phát hiện ngay hóa đơn chỉnh sửa, ảnh chụp màn hình giả hoặc chuyển khoản sai số tiền/trạng thái.

### 4.3. Ý nghĩa Kỹ thuật, Bảo mật & Sẵn sàng Triển khai (*Secure-by-Design*)
- **Chống ảo giác & chống Prompt Injection bằng kiến trúc phân quyền rõ ràng:** Điểm rủi ro và phân loại gian lận luôn do **5 công cụ định lượng thuần TypeScript** quyết định gốc; chuỗi dự phòng 3 tầng (`gemini-3.5-flash-lite` → `gemini-3.1-flash-lite` → `Deterministic Engine`) đảm bảo hệ thống **không bao giờ sập hay mất khả năng bảo vệ** kể cả khi API AI quá tải hoặc mất kết nối.
- **Đã triển khai & kiểm chứng thực tế trên hạ tầng Cloud `$0/month` Free-Tier:**
  - **Hosting:** Netlify Production (`https://aegisops-momo-contest-2026.netlify.app`), chuẩn hóa xác thực IP client chống giả mạo header proxy qua `x-nf-client-connection-ip`.
  - **Database:** Neon PostgreSQL `18.7` (TLS `verify-full` + `channel_binding=require`), lưu bền vững trạng thái phiên cô lập và sổ cái mô phỏng.
  - **Rate Limiting & Quota:** Upstash Redis phân tán (`/multi-exec` nguyên tử, fail-closed khi mất kết nối).
  - **Vận hành tự động:** Tác vụ dọn dẹp phiên hết hạn có giới hạn (`GET /api/internal/cleanup`, xác thực `CRON_SECRET` thời gian hằng số `timingSafeEqual`) chạy định kỳ hàng ngày lúc `03:00 UTC` (`10:00` giờ Việt Nam) qua `cron-job.org`.
  - **Chất lượng được bảo chứng tự động:** `159/159` Unit/Security/Red-Team tests (Vitest), `11/11` Playwright E2E Golden Path scenarios và CI tự động trên GitHub Actions.

### 4.4. Ranh giới Trung thực của Phiên bản Dự thi
Để đảm bảo tính minh bạch tuyệt đối với Ban Giám Khảo:
- **Đã chạy thật trên Cloud:** Ứng dụng web HTTPS công khai, gọi Gemini API trực tiếp, lưu trữ ACID trên Neon PostgreSQL, giới hạn tần suất phân tán trên Upstash Redis, và lịch dọn phiên tự động trên `cron-job.org`.
- **Phạm vi mô phỏng cuộc thi:** Dữ liệu khách hàng/giao dịch là dữ liệu tổng hợp; cổng báo cáo SIMO là bản tin mô phỏng cục bộ (chưa kết nối mạng NHNN/A05 thật); tín hiệu 3D Liveness/PAD là mô phỏng tham chiếu (`CERTIFICATION_NOT_VERIFIED`); bộ chuyển vai trò 1-Click L1/L2 phục vụ trình diễn cuộc thi (được thiết kế khóa qua `AEGIS_ENABLE_DEMO_PERSONA_SWITCH=false` ở môi trường doanh nghiệp để thay bằng SSO/OIDC).

---

## 5. Hướng dẫn Kiểm chứng Toàn bộ Chức năng & Kịch bản cho Ban Giám Khảo

Ban Giám Khảo có thể trải nghiệm trực tiếp tại **`https://aegisops-momo-contest-2026.netlify.app`** hoặc trên máy cục bộ (`http://localhost:3000`).

> **Tài liệu Hướng dẫn Đầy đủ từng Bước (36 Trường hợp Kiểm thử / 9 Nhóm Năng lực):**  
> Xem sổ tay chi tiết tại **[docs/JUDGE_COMPLETE_TESTING_GUIDE.md](docs/JUDGE_COMPLETE_TESTING_GUIDE.md)** và kịch bản thuyết trình 3 phút tại **[docs/DEMO_VIDEO_3MIN_SCRIPT.md](docs/DEMO_VIDEO_3MIN_SCRIPT.md)**.

### 5.1. Lộ trình Trải nghiệm Nhanh 3 Bước (Golden Path — ~2 phút)
1. **Bước 1 — Khám phá Dashboard & Chạy AI Điều tra:** Mở ứng dụng, bấm **`Xem Demo Tự động 15s`** hoặc mở **Vụ #1 `ALT-APP-003` (Lừa đảo giả danh Công an)** → bấm **`Bước 1: Chạy AI Điều tra`** để xem tiến trình phân tích 5 công cụ định lượng, huy hiệu nguồn (`ai-source-badge`) và tóm tắt có cấu trúc.
2. **Bước 2 — Soi Bằng chứng & Duyệt Playbook 1-Click:** Bấm vào các nút trên đồ thị BFS hoặc mã bằng chứng (`EVD-103`, `TXN-9011`, `DEV-EMU-666`) để xem dữ liệu gốc, ảnh đoạn chat mẫu và phân tích tên miền phishing. Bấm **`Bước 2: Duyệt & Bật Lá chắn (1-Click)`**.
3. **Bước 3 — Kiểm chứng Chặn trên Ví MoMo & Hoàn tiền Clawback:** Mở **Ví MoMo** → thử chuyển tiền tới `1903999888777` để chứng kiến **chặn cứng (`BLOCKED`, số dư `45.000.000 ₫` giữ nguyên)**; quay lại `ALT-APP-003` bấm **`Thu hồi & Hoàn trả GD Đã Hạch toán (TXN-9011)`** để kiểm chứng hoàn `25.000.000 ₫` về ví nạn nhân trên sổ cái hợp nhất.

### 5.2. Bản đồ Toàn bộ 9 Nhóm Chức năng & Trường hợp Hệ thống Hỗ trợ

| Nhóm | Chức năng / Kịch bản có thể kiểm chứng trực tiếp | Điểm nhấn kỹ thuật & nghiệp vụ |
|---:|---|---|
| **1** | **Dashboard Tổng quan & Điều hành:** Auto-Demo 15s, 4 KPI đo thực tế, lọc kịch bản, `Ctrl+K`, **Live Feed**, **Nhập/Xuất CSV & JSON**, **Shadow Mode** | Không hardcode KPI; nhập hàng loạt CSV/JSON chấm điểm động tức thời |
| **2** | **4 Kịch bản Thực chiến Gốc:** `ALT-APP-003` (APP Fraud, `95/100`), `ALT-ATO-001` (Cyber ATO & Smurfing `0.99`, `99/100`), `ALT-BLG-002` (Race Condition `12 req/140ms` & Webhook HMAC, `99/100`), `ALT-FPR-004` (Viện phí cấp cứu hợp lệ, `14/100`) | Phủ trọn 3 chủ đề cuộc thi (**Trợ lý AI + An ninh mạng + Chống lừa đảo**) và chứng minh **tránh khóa oan khách hàng thật** |
| **3** | **Trung tâm Điều tra Hợp nhất:** Đồ thị dòng tiền BFS (`@xyflow/react`), 5 tab bằng chứng gốc + giải phẫu link Phishing/`.APK`, **Xem Song song Ví (Split-Screen)**, **Gom nhóm AI (Batch Triage 1-Chạm)**, **Hỏi đáp Copilot** | Tích hợp `Citation Validator` loại bỏ mã trích dẫn ảo; hiển thị minh bạch nguồn AI vs định lượng |
| **4** | **Quản trị Ngân hàng & HITL:** Chuyển vai trò **L1 Maker → L2 Checker → End-User** (khóa quyền duyệt vượt cấp & khóa gom nhóm ở L1), **Adaptive HITL Memory** (tạo quy tắc an toàn có TTL & nút **Thu hồi Revoke**) | Nguyên tắc 4 mắt (*Four-Eyes Principle*) cưỡng chế ở cả UI và backend API |
| **5** | **Nhập Hồ sơ Kiểm thử Động (Live Sandbox):** **Biểu mẫu 4 Phần** (4 mẫu sẵn `PRESET-SAFE / APP-FRAUD / CYBER-ATO / RACE-LOGIC` tính điểm động `120ms`), **3 ảnh mẫu Vision** (Shipper / Bill giả / CTV), hoặc **tự dán văn bản / tải ảnh PNG/JPEG/WebP** | Chấp nhận dữ liệu bất kỳ của Ban Giám Khảo, bóc tách thực thể, dựng đồ thị và chặn đúng STK vừa tạo trên Ví |
| **6** | **Ví MoMo & Lá chắn Thời gian thực:** Cảnh báo làm nguội **`HELD`** (trước khi duyệt, không trừ tiền sớm), chặn cứng **`BLOCKED`** (sau khi duyệt), chuyển tiền hợp lệ **`SETTLED`** tới `1188999000888` trừ số dư thật, **1-Click Clawback** chống hoàn trùng, và **giải mã VietQR EMVCo TLV cục bộ** (`QR-SPOOF-GHN`, `QR-HOSPITAL-SAFE`, tự nhập TLV) | Phòng vệ chủ động trước khi chuyển tiền + sổ cái hợp nhất + thẻ gỡ bùa tâm lý |
| **7** | **Chế độ Tiểu thương (Merchant Mode):** Đủ **5 trường hợp đối soát sổ cái (Case A: Khớp thật, Case B: Bill sửa tiền `1K → 15M`, Case C: Không tồn tại, Case D: GD bị chặn, Case E: Sai STK nhận)**, **Loa Soundbox tiếng Việt**, **AI Vision quét ảnh hóa đơn** & chặn tệp `.SVG` độc hại | Tách bạch tuyệt đối AI OCR khỏi Sổ cái gốc (`POST /api/merchant/verify` & `/api/merchant/vision`); không lưu ảnh base64 vào `localStorage` |
| **8** | **Pháp lý NHNN, In PDF & Audit Trail:** Đối chiếu **QĐ 2345**, **TT 50/2024 sửa bởi TT 77/2025** (minh bạch `CERTIFICATION_NOT_VERIFIED`), **Luật 91/2025 & NĐ 356/2025** (`LEGAL_REVIEW_REQUIRED`), xuất **PDF Print CSS nền trắng**, **Bản tin SIMO mô phỏng HMAC-SHA-256**, và **Nhật ký Audit** lọc theo tác nhân | Tuân thủ pháp lý Việt Nam trung thực, sẵn sàng kiểm toán |
| **9** | **Bảo mật & Hạ tầng Cloud Trực tuyến:** `GET /api/health` (`PRODUCTION_SHARED_INFRA_READY`), **cô lập đa phiên + lưu bền vững Neon PostgreSQL**, chặn truy cập không cookie (`401`), chặn giả mạo proxy IP (`429` trên Netlify + Upstash Redis), **dọn phiên tự động 03:00 UTC**, **18/18 ô Responsive** và **159 Unit + 11 Playwright E2E** | Chứng minh độ chín kỹ thuật và sẵn sàng triển khai thực tế |

---

## 6. Hướng dẫn Chạy Dự án Cục bộ (Local Development & Testing)

### Yêu cầu Môi trường
- **Node.js:** `24.x LTS` (`>=24.0.0 <25.0.0`)
- **npm:** `>= 10.x`

### Các bước Khởi chạy
1. **Cài đặt thư viện:**
   ```bash
   npm install
   ```
2. **Cấu hình biến môi trường cục bộ (tùy chọn để bật Live Gemini):**
   Sao chép `.env.example` thành `.env.local` và điền `GEMINI_API_KEY` (Google AI Studio). Nếu không cấu hình khóa API, hệ thống vẫn chạy đầy đủ ở chế độ **Deterministic Fallback** an toàn:
   ```env
   GEMINI_API_KEY=your_gemini_api_key_here
   GEMINI_PRIMARY_MODEL=gemini-3.5-flash-lite
   GEMINI_FALLBACK_MODEL=gemini-3.1-flash-lite
   AI_RATE_LIMIT_PER_MIN=12
   AI_SANDBOX_RATE_LIMIT_PER_MIN=8
   AI_OCR_RATE_LIMIT_PER_MIN=6
   AI_IP_BURST_LIMIT_PER_MIN=36
   ```
   *(Cấu hình đầy đủ cho Production — Neon PostgreSQL TLS, Upstash Redis, các bí mật tách miền và quy trình triển khai — xem tại [docs/DEPLOYMENT_RUNBOOK.md](docs/DEPLOYMENT_RUNBOOK.md)).*
3. **Chạy môi trường phát triển:**
   ```bash
   npm run dev
   ```
   Truy cập: `http://localhost:3000`
4. **Chạy toàn bộ cổng kiểm định chất lượng (Typecheck, Lint, Unit/Red-Team Tests, Production Build & Playwright E2E):**
   ```bash
   npm run typecheck
   npm run lint
   npm test
   npm run build
   npm run test:e2e
   ```

---

## 7. Kiến trúc Công nghệ (Clean Architecture 4 Lớp)

- **`src/domain/` (Pure Domain & Deterministic Forensics):**
  - `types.ts`: Toàn bộ thực thể nghiệp vụ (`StandardCaseInputSpec`, `OperatorRole`, `WorkspaceNotification`) và Zod schemas.
  - `forensics-analyzers.ts`: 5 công cụ truy vết định lượng thuần TypeScript (`analyzeAccountProfile`, `analyzeMuleGraph`, `inspectCyberSession`, `detectBusinessLogicAbuse`, `correlateScamCampaign`) cùng Z-Score, Smurfing Entropy, Bipartite Clustering và Risk Attribution.
  - `batch-io.ts`: Nhập & xuất dữ liệu hàng loạt CSV (UTF-8 BOM) / JSON chuẩn RFC-4180.
  - `campaign-correlator.ts`: Gom nhóm chiến dịch đa vụ án (`Batch Triage`) phát hiện băng nhóm chung thiết bị.
  - `vietqr-inspector.ts`: Giải mã chuỗi EMVCo VietQR & kiểm tra khớp tên pháp lý NAPAS.
  - `sandbox-synthesizer.ts`: Tổng hợp đồ thị động, trích xuất thực thể và chấm điểm tức thời cho **Biểu mẫu 4 Phần** & Live Sandbox.
  - `shield-evaluator.ts`: Động cơ đánh giá & chặn giao dịch thời gian thực trên Ví mô phỏng + Đèn Tín nhiệm 3 Màu.
  - `compliance-report.ts`: Khởi tạo Biên bản Điều tra & Đối chiếu Pháp lý QĐ 2345 / TT 50/2024 (sửa đổi bởi TT 77/2025) / Luật 91/2025/QH15 & NĐ 356/2025/NĐ-CP / SIMO mô phỏng.
- **`src/application/` (Orchestration & Guardrails):**
  - `citation-validator.ts`: Kiểm định tham chiếu mã bằng chứng (`validateAndRepairCitations`), loại bỏ mã bằng chứng không tồn tại khỏi chip trích dẫn.
  - `workspace-orchestrator.ts`: Điều phối luồng điều tra, **kiểm soát kép Maker–Checker L1/L2**, nhập CSV/JSON, hỏi đáp Copilot và mô phỏng Ví/Tiểu thương.
- **`src/infrastructure/` (Adapters, Persistence & Security):**
  - `gemini-agent.ts`: Kết nối Google Gemini Multimodal API với chuỗi dự phòng 3 tầng, circuit breaker và kiểm soát quota phân tán.
  - `persistence-adapter.ts` & `workspace-store.ts`: Lưu trữ cô lập theo phiên giám khảo trên Neon PostgreSQL (TLS `verify-full`) hoặc bộ nhớ cục bộ khi chạy dev, hỗ trợ dọn phiên hết hạn có giới hạn.
  - `security-guard.ts`, `session-auth.ts`, `privacy-hasher.ts` & `api-schemas.ts`: Xác thực cookie ký HMAC HttpOnly, bảo vệ IP proxy Netlify (`x-nf-client-connection-ip`), Upstash Redis `/multi-exec` rate limiter, giới hạn payload ảnh tải lên (nhị phân ảnh gốc tối đa `3,000,000` bytes / `3.0 MB`, base64 data URL tối đa `4,000,064` ký tự, JSON tối đa `4,194,304` bytes / `4 MiB`) và chống XSS.
  - `seed-scenarios.ts`: Bộ dữ liệu mô phỏng thực chiến cho 4 kịch bản Fintech.
- **`src/presentation/` & `src/app/` (Next.js 15 App Router & OLED Dark UI):**
  - Giao diện 5 phân hệ responsive trên mọi màn hình (Desktop, Laptop, Tablet, Mobile), đồ thị tương tác `@xyflow/react`, mô phỏng Ví/Soundbox và xuất biên bản PDF.

---

## 8. Minh bạch Tài sản có sẵn, Thư viện Mã nguồn mở & Công cụ AI đã dùng

### 8.1. Tài sản có sẵn (Pre-existing Assets)
- **Không sử dụng mã nguồn sản phẩm có sẵn:** Toàn bộ mã nguồn ứng dụng (`src/`), bộ công cụ Deterministic Forensics, bộ dữ liệu mô phỏng 4 kịch bản (`seed-scenarios.ts`), ảnh minh họa SVG và bộ kiểm thử (`tests/`) được xây dựng mới 100% trong khuôn khổ cuộc thi.
- **Tri thức chuyên môn tham khảo:** Các chuẩn mực về kiểm thử bảo mật web/API (OWASP WSTG, phân loại lỗ hổng ATO/Session/Business Logic) và kiến trúc phần mềm được dùng làm tài liệu định hướng phát triển và không đóng gói trong kho mã nguồn công khai này.

### 8.2. Danh sách Thư viện Mã nguồn mở Trực tiếp (`package.json` — 9 Production + 12 Development)

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

### 8.3. Công cụ AI đã sử dụng (AI Tools Disclosure)
1. **Thành phần AI cốt lõi bên trong sản phẩm (Runtime Core AI):**
   - **Google Gemini API (`gemini-3.5-flash-lite` mặc định & `gemini-3.1-flash-lite` dự phòng qua cấu hình):** Hỗ trợ phân tích bằng chứng mô phỏng đa phương thức (ảnh đoạn chat lừa đảo mẫu / hóa đơn tiểu thương mẫu), bóc tách thực thể trong Live Sandbox, tóm tắt kết quả từ 5 công cụ Forensics và trả lời hỏi đáp của chuyên viên vận hành (quyết định rủi ro gốc luôn do công cụ định lượng nắm giữ).
2. **Công cụ AI hỗ trợ phát triển (Development Assistant):**
   - **Google Antigravity IDE Agent:** Hỗ trợ thiết kế kiến trúc Clean Architecture, viết mã nguồn TypeScript, kiểm thử tự động và biên soạn tài liệu kỹ thuật dưới sự chỉ đạo và kiểm duyệt của đội thi.

---

## License & Usage

- **Public Portfolio Viewing:** This repository is publicly available for viewing and technical evaluation as a portfolio project.
- **No Open-Source License Grant:** No open-source license is granted by the AegisOps project owner (`"license": "UNLICENSED"` in `package.json`). No additional project-level permission to use, modify, redistribute, or commercially reuse AegisOps-owned code is granted by this repository.
- **GitHub Platform Terms:** Public repository viewing and forking within GitHub remain governed by GitHub's Terms of Service.
- **Applicable Law:** Any rights available under applicable law remain unaffected.
- **Third-Party Dependencies & Assets:** Third-party packages, fonts, and external assets remain independent from the AegisOps project license status and are governed by their respective licenses and terms.
