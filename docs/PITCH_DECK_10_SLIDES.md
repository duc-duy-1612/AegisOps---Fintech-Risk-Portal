# NỘI DUNG 10 TRANG SLIDE THUYẾT TRÌNH CHUNG KẾT: AEGISOPS
*(Lưu ý quy chế: Tối đa 10 trang, định dạng PDF, dùng cho vòng Chung kết và không được chỉnh sửa sau khi nộp)*

---

## SLIDE 1: TRANG BÌA & TUYÊN NGÔN GIÁ TRỊ
- **Tên sản phẩm:** **AEGISOPS** — *AI-Powered Fintech Fraud, Cyber Defense & Real-Time User Protection Workspace*
- **Khẩu hiệu:** *"Từ điều tra thủ công rời rạc sang quy trình khép kín có kiểm định — Chuyển hóa công cụ định lượng và Trợ lý AI thành lá chắn bảo vệ Ví người dùng."*
- **Phủ trọn 3 Chủ đề Cuộc thi:**
  1. **Trợ lý AI:** Hỗ trợ điều tra đa nguồn, tổng hợp hồ sơ có kiểm định tham chiếu mã bằng chứng & đề xuất Playbook dưới sự phê duyệt của chuyên viên.
  2. **An ninh mạng:** Truy vết chiếm đoạt tài khoản (Persistent ATO), đánh cắp phiên & tấn công Race Condition (TOCTOU) / giả mạo Webhook HMAC.
  3. **Chống lừa đảo:** Hỗ trợ đọc ảnh chụp đoạn chat thao túng tâm lý (APP Fraud), giải mã VietQR EMVCo cục bộ & kích hoạt Lá chắn Ví người dùng mô phỏng.

---

## SLIDE 2: ĐỐI TƯỢNG NGƯỜI DÙNG & 4 NỖI ĐAU THỰC TẾ TRONG FINTECH
- **Đối tượng Người dùng Kép (Dual Personas):**
  - *Trực tiếp (Primary):* Đội ngũ Vận hành Rủi ro, Chống gian lận & An ninh mạng Fintech (**Risk Ops / Fraud Analysts / SecOps L1–L2**).
  - *Hưởng lợi trực tiếp (Downstream):* **Người dùng cá nhân & Tiểu thương** trên Ví điện tử.
- **4 Điểm nghẽn Chí mạng Hiện nay:**
  1. **Phân mảnh công cụ (Alert Fatigue):** Chuyên viên phải mở 6–7 màn hình rời rạc (Ledger, Auth Log, Graph, API Log, ảnh Ticket CSKH), mất **20–40 phút/vụ**.
  2. **Tốc độ tẩu tán tiền tính bằng giây:** Tội phạm dùng bot chia nhỏ tiền (*Smurfing*) qua cụm tài khoản rác (*Mule Ring*) trước khi con người kịp tra cứu xong.
  3. **Điểm mù trước Lừa đảo Thao túng Tâm lý (APP Fraud):** Chính nạn nhân tự mở điện thoại thật, tự quét khuôn mặt chuyển tiền cho kẻ giả danh Công an/Shipper.
  4. **Ác mộng "Khóa oan khách hàng thật" (False Positives):** Rule cứng khóa nhầm khách chuyển tiền viện phí ban đêm trên điện thoại mới.

---

## SLIDE 3: VÌ SAO QUYẾT ĐỊNH 2345/QĐ-NHNN VẪN CẦN AEGISOPS?
- **Bối cảnh Pháp lý Hiện hành:** Quyết định 2345/QĐ-NHNN (phân loại theo nhóm giao dịch Loại C/D: chuyển tiền cá nhân `>10M/lần` hoặc cộng dồn `T_ksth >20M/ngày`, thanh toán hàng hóa/dịch vụ hợp pháp `>100M`, kích hoạt lần đầu/thiết bị mới), Thông tư 50/2024/TT-NHNN (sửa đổi, bổ sung bởi Thông tư 77/2025/TT-NHNN hiệu lực 01/03/2026) và Luật Bảo vệ dữ liệu cá nhân 91/2025/QH15 + Nghị định 356/2025/NĐ-CP (hiệu lực 01/01/2026, Điều 42 bãi bỏ NĐ 13/2023/NĐ-CP).
- **3 Lỗ hổng Tội phạm dùng để "Lách" Sinh trắc học:**
  1. **Thao túng tâm lý thời gian thực (In-Call Coercion):** Giữ nạn nhân trong cuộc gọi đe dọa kéo dài và hướng dẫn nạn nhân paste STK rồi tự quét FaceID của chính mình.
  2. **Tráo mã VietQR (NAPAS Name-Check Mismatch):** Gửi ảnh QR ghi tên doanh nghiệp/cổng hoàn tiền nhưng payload EMVCo bên trong trỏ về tài khoản cá nhân Mule.
  3. **Chiếm đoạt Phiên sau xác thực (Persistent Session Hijack & Token Replay)** trên thiết bị giả lập và khai thác xung đột đồng thời (*Race Condition TOCTOU*).

---

## SLIDE 4: GIẢI PHÁP ĐỘT PHÁ — VÒNG KHÉP KÍN 2 CHIỀU ĐỊNH LƯỢNG & LÁ CHẮN MÔ PHỎNG
- **Chiều 1 (Từ Ví Người dùng → Bàn làm việc Fintech):**
  - Cảm biến hành vi trên Ví (*In-Call Telemetry + Clipboard Paste + VietQR Inspector*) hoặc nút báo cáo khẩn cấp đẩy sự cố trực tiếp về Hàng đợi AegisOps.
- **Chiều 2 (Từ Bàn làm việc Fintech → Lá chắn Ví Người dùng):**
  - **Bước 1:** 5 Công cụ Deterministic Forensics + Trợ lý Gemini Multimodal tự động tổng hợp dữ liệu, vẽ đồ thị mạng lưới và gắn mã bằng chứng hợp lệ.
  - **Bước 2 (1-Click Human-in-the-Loop):** Chuyên viên L1 đề xuất / Quản lý L2 duyệt Playbook theo cơ chế kiểm soát kép 4-Eyes.
  - **Bước 3:** Luật bảo vệ kích hoạt ngay trên Ví mô phỏng cục bộ, chặn giao dịch (`BLOCKED`) hoặc tạm giữ làm nguội (`HELD`, không trừ tiền) kèm **Thẻ Gỡ bùa Thao túng Tâm lý**.

---

## SLIDE 5: KIẾN TRÚC LAI ĐỊNH LƯỢNG GỐC + TRỢ LÝ AI (HYBRID DETERMINISTIC + AI-ASSISTED)
- **Tầng 1 — Deterministic Forensics Engine (Pure TypeScript — Quyết định gốc):**
  - Tính toán nhất quán số tiền, truy vết đồ thị BFS đa nạn nhân, kiểm tra cờ `survived_credential_reset`, đếm xung đột mili-giây (`12 req/100ms`) và xác thực chữ ký HMAC.
- **Tầng 2 — Gemini Multimodal Investigation Assistant (`gemini-3.5-flash-lite` / cấu hình dự phòng `gemini-3.1-flash-lite`):**
  - Hỗ trợ đọc ảnh chụp màn hình đoạn chat lừa đảo / hóa đơn tiểu thương (Vision OCR), diễn giải nguyên nhân gốc bằng tiếng Việt và trả lời Q&A cho chuyên viên (kèm phòng vệ prompt-injection & không thể ghi đè quyết định rủi ro gốc).
- **Tầng 3 — Deterministic Citation Reference Validator (`validateAndRepairCitations`):**
  - Kiểm định tính tồn tại của mã bằng chứng trích dẫn (`TXN-*`, `LOG-*`, `DEV-*`, `EVT-*`, `EVD-*`) thuộc đúng vụ án (loại bỏ mã không tồn tại; chuyên viên vẫn rà soát ngữ nghĩa nội dung gốc).

---

## SLIDE 6: THUẬT TOÁN ĐỊNH LƯỢNG & CHỐNG KHÓA OAN (HUMAN-CENTERED AI)
- **4 Chỉ số Đồ thị & Thống kê Thời gian thực:**
  1. **Z-Score Deviation ($Z = \frac{X - \mu}{\sigma}$):** Đo độ lệch đột biến giá trị giao dịch so với lịch sử cá nhân.
  2. **Smurfing Entropy Index ($S = 1 - CV \in [0, 1]$):** Phát hiện hành vi chia nhỏ tiền đều nhau để rửa tiền (ví dụ 3 lệnh 16M liên tiếp đạt Entropy `0.99`).
  3. **Bipartite Device Clustering:** Hệ số gom cụm nhiều tài khoản Mule cùng đăng nhập trên 1 mã thiết bị giả lập (`DEV-EMU-666`).
  4. **Cross-Victim Fan-In:** Số nạn nhân độc lập cùng chuyển tiền vào 1 tài khoản đích trong cửa sổ thời gian ngắn.
- **Mô hình Phân rã Trọng số SHAP-like (Risk Boosters `+đ` vs. Trust Dampeners `-đ`):**
  - Áp dụng trọng số giảm trừ tin cậy (`-22đ` Đơn vị y tế uy tín, `-16đ` FaceID + NFC CCCD chính chủ) giúp kéo điểm rủi ro ca đóng viện phí đêm từ `52đ` xuống **`14/100 (An toàn — Không khóa oan khách hàng)`**.

---

## SLIDE 7: TRẢI NGHIỆM SẢN PHẨM & 5 KỊCH BẢN THỰC CHIẾN LIVE
- **Giao diện OLED Dark Command Center + Chế độ Song song (Side-by-Side Split-Screen):** Đặt Bàn làm việc Fintech và Điện thoại Ví Người dùng cạnh nhau trên cùng 1 màn hình.
- **5 Kịch bản Kiểm chứng Toàn diện:**
  1. **`ALT-APP-003` (APP Fraud Giả Công an):** Đọc ảnh chat + phát hiện đang nghe cuộc gọi lạ 19 phút → Bật lá chắn chặn nạn nhân tiếp theo trên Ví.
  2. **`ALT-ATO-001` (Cyber ATO & Mule Ring):** Phiên sống sót sau đổi mật khẩu + chia nhỏ 48M qua 3 TK Mule dùng chung máy giả lập.
  3. **`ALT-BLG-002` (Business Logic Race TOCTOU):** 12 request đồng thời/140ms nhân bản voucher + giả mạo callback thiếu HMAC.
  4. **`ALT-FPR-004` (Smart False Positive):** Bảo vệ khách VIP đóng viện phí cấp cứu lúc 23:45 đêm không bị khóa oan.
  5. **`Live Multimodal Sandbox`:** Thư viện 3 ảnh lừa đảo mẫu 1-chạm + cho phép BGK tải ảnh chụp màn hình lên để Gemini Vision OCR hỗ trợ bóc tách STK và dựng đồ thị động.

---

## SLIDE 8: KIẾN TRÚC KỸ THUẬT CHỊU LỖI & ĐỐI CHIẾU PHÁP LÝ MINH BẠCH
- **Clean Architecture 4 Lớp (`domain` → `application` → `infrastructure` → `presentation`):** Kiểm thử tự động toàn diện (Unit/Integration Vitest + Playwright Chromium E2E) bao phủ Sổ cái Kép & Clawback GD đã hạch toán, Merchant Vision & Soundbox mô phỏng, Quét Link Phishing/.APK, EMVCo TLV VietQR Parser cục bộ, Batch Triage 1-Chạm, Adaptive HITL & Maker–Checker L1/L2.
- **Enterprise SaaS App Shell 5 Phân hệ:** Menu dọc thu gọn, Tag Box lọc nhanh, Dashboard Tổng quan (KPI thực đo, không cộng ảo), Biểu mẫu Hồ sơ 4 Phần tính toán động & Chế độ giả lập vai trò Demo L1/L2/End-User.
- **Session Isolation & Persistence Architecture:** Cô lập phiên ký HMAC `HttpOnly` (`SessionDeltaSnapshot`) và sẵn sàng bộ chuyển đổi PostgreSQL/Upstash Redis cho giai đoạn triển khai cloud.
- **Chuỗi Dự phòng AI 3 Tầng:** `gemini-3.5-flash-lite` → `gemini-3.1-flash-lite` (cấu hình dự phòng cho dự án Google mới) → `Deterministic Forensics Engine` (hiển thị minh bạch nguồn thực thi & thông báo fallback đã khử nhạy cảm trên `ai-source-badge`).
- **Biên bản Đối chiếu Pháp lý Minh bạch:** Xuất hồ sơ PDF/Markdown ánh xạ yêu cầu **QĐ 2345**, **TT 50/2024 (sửa đổi bởi TT 77/2025 — PAD `CERTIFICATION_NOT_VERIFIED`)**, **Luật 91/2025/QH15 & NĐ 356/2025/NĐ-CP (`LEGAL_REVIEW_REQUIRED`)** và bản tin JSON **SIMO mô phỏng** (giả danh PII bằng HMAC-SHA-256; không phải kết nối thực tế).

---

## SLIDE 9: HIỆU QUẢ ĐỊNH LƯỢNG & GIÁ TRỊ MANG LẠI
| Chỉ số / Năng lực | Quy trình Truyền thống | Với **AegisOps Workspace** |
| :--- | :--- | :--- |
| **Gom dữ liệu & điều tra 1 vụ** | Tra cứu rời rạc nhiều màn hình | **Tự động tổng hợp đa nguồn + đồ thị BFS + AI hỗ trợ trên 1 màn hình** |
| **Quản trị trích dẫn bằng chứng** | Thủ công, dễ sót | **Kiểm định tham chiếu mã bằng chứng (Reference Validation) + chuyên viên rà soát** |
| **Kích hoạt Lá chắn Ví mô phỏng** | Chờ đồng bộ thủ công | **Kích hoạt tức thì trong phiên sau khi L2 phê duyệt (mô phỏng cục bộ)** |
| **Bảo vệ tâm lý người dùng cuối** | Chỉ báo lỗi giao dịch khô khan | **Thẻ Gỡ bùa Thao túng Tâm lý, `HELD` Cooling-Off không trừ tiền & giải mã VietQR** |
| **Giảm thiểu khóa oan khách hàng thật** | Rule cứng dễ khóa nhầm | **Trọng số giảm trừ Trust Dampeners & Adaptive HITL có giới hạn biên** |

---

## SLIDE 10: LỘ TRÌNH TRIỂN KHAI THỰC TẾ & TẦM NHÌN TƯƠNG LAI
- **Giai đoạn 1 (Dùng được ngay hôm nay):** Triển khai làm AI Copilot Workspace cho đội ngũ Risk Ops / Trust & Safety và cổng kiểm tra VietQR / Lá chắn cảnh báo trên ứng dụng Ví điện tử.
- **Giai đoạn 2 (Tích hợp Liên thông):** Kết nối trực tiếp luồng Kafka/Webhook giao dịch thời gian thực và đồng bộ hai chiều với cơ sở dữ liệu tài khoản nghi vấn SIMO của Ngân hàng Nhà nước.
- **Giai đoạn 3 (Federated Fraud Defense):** Mở rộng Lá chắn AI bảo vệ toàn diện hệ sinh thái Tiểu thương (Merchant VietQR) và Người dùng cá nhân trên không gian số Việt Nam.
