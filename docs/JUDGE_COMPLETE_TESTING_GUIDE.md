# Sổ tay Hướng dẫn Trải nghiệm & Kiểm chứng Toàn bộ Chức năng AegisOps (Dành cho Ban Giám Khảo)

**Nền tảng:** AegisOps — AI-Powered Fintech Fraud, Cyber Defense & Real-Time User Protection Workspace  
**Bản Live Online:** `https://aegisops-momo-contest-2026.netlify.app`  
**Bản Local:** `http://localhost:3000` (`npm run dev` hoặc `npm run build && npm start`)  
**Ranh giới dữ liệu:** 100% dữ liệu mô phỏng tổng hợp (*Synthetic-Data-Only*). Không nhập CCCD, số điện thoại, số tài khoản hoặc ảnh hóa đơn ngân hàng thật.

---

## Bản đồ Phạm vi Năng lực Hệ thống (System Capability Map)

Tài liệu này giúp Ban Giám Khảo kiểm chứng **toàn bộ độ rộng (5 phân hệ, 13 API routes, 15 module nghiệp vụ miền)** và **độ sâu (4 kịch bản thực chiến, 5 trường hợp đối soát Tiểu thương A–E, 4 mẫu Biểu mẫu 4 Phần, 3 ảnh mẫu Vision, Maker–Checker L1/L2, HITL Memory, Clawback, VietQR EMVCo, Compliance PDF/SIMO, và chốt chặn bảo mật Cloud)** chỉ trong 10–15 phút.

| Nhóm | Phân hệ / Năng lực | Số kịch bản kiểm thử | Mục đích chứng minh |
|---:|---|---:|---|
| **1** | Dashboard Tổng quan, KPI đo thực tế, CSV/JSON, Shadow Mode & `Ctrl+K` | 4 trường hợp | Không gian làm việc thương mại, không bịa chỉ số, hỗ trợ thao tác hàng loạt |
| **2** | 4 Kịch bản Thực chiến Gốc (`APP Fraud`, `Cyber ATO`, `Race/HMAC`, `False Positive`) | 4 trường hợp | Phủ đủ 3 chủ đề cuộc thi + năng lực tránh khóa oan khách hàng thật |
| **3** | Trung tâm Điều tra: Đồ thị BFS, 5 Tab Bằng chứng, Split-Screen, Gom nhóm AI & Copilot | 4 trường hợp | Hợp nhất điều tra trên 1 màn hình, chống ảo giác bằng `Citation Validator` |
| **4** | Quản trị Ngân hàng: Maker–Checker (L1/L2/End-User) & Adaptive HITL Memory | 2 trường hợp | Kiểm soát kép chuẩn ngân hàng, con người nắm quyền quyết định gốc |
| **5** | Nhập Hồ sơ Kiểm thử Động (Biểu mẫu 4 Phần, 3 Ảnh mẫu OCR & Tải ảnh tự do) | 3 trường hợp | Hệ thống xử lý dữ liệu đầu vào động thật, không hardcode kịch bản tĩnh |
| **6** | Ví MoMo Mô phỏng: Làm nguội `HELD`, Chặn `BLOCKED`, Chuyển thật `SETTLED`, Clawback & VietQR | 5 trường hợp | Vòng khép kín từ phòng Risk tới bảo vệ ví người dùng & thu hồi sổ cái kép |
| **7** | Tiểu thương: Đối soát Sổ cái 5 Case (A–E), Loa Soundbox & Vision OCR chống `.SVG` | 6 trường hợp | Chặn nạn bill chuyển khoản giả, tách bạch AI OCR khỏi quyền sửa sổ cái gốc |
| **8** | Hồ sơ Pháp lý NHNN (QĐ 2345, TT 50/77, Luật 91/2025), In PDF, SIMO & Audit Trail | 4 trường hợp | Tuân thủ pháp lý Việt Nam trung thực, không tuyên bố chứng nhận chưa kiểm chứng |
| **9** | Kiểm chứng Kỹ thuật, Bảo mật Cloud, Đa phiên, Proxy IP, Cron & 170 Bài Test Tự động | 4 trường hợp | Kiến trúc *Secure-by-Design* đã chạy thật trên Netlify + Neon + Upstash + Gemini |

---

## NHÓM 1 — Dashboard Tổng quan, KPI Đo Thực tế & Công cụ Điều hành

### Trường hợp 1.1 — Trình diễn Tự động 15 giây (*Auto-Demo*)
- **Thao tác:** Ở góc trên bên phải thanh công cụ hoặc trong banner đầu Dashboard, bấm **`Xem Demo Tự động 15s`** (hoặc **`Chạy Demo 15s`**).
- **Kết quả kỳ vọng:** Hệ thống tự động dẫn qua chu trình khép kín từ chọn vụ việc → chạy AI điều tra → duyệt Playbook L2 → mở Ví MoMo kiểm chứng chặn giao dịch. Có thể bấm **`Đặt lại Dữ liệu Gốc`** ở thanh menu trái bất kỳ lúc nào để đưa phiên về trạng thái ban đầu.

### Trường hợp 1.2 — Kiểm chứng 4 KPI Đo Thực tế, Lọc Danh mục & Bảng Lệnh Nhanh (`Ctrl + K`)
- **Thao tác:**
  1. Ở trạng thái khởi tạo mới, quan sát 4 thẻ KPI trên Dashboard: **`Đã chặn & thu hồi`** (`0 ₫`, kèm số tiền đang tạm giữ), **`Độ trễ AI trung bình`** (`Chưa có dữ liệu`), **`Lá chắn Ví & Chờ duyệt`** (`0 lá chắn • 4 chờ xử lý`), **`Tránh khóa oan`** (`0 cảnh báo`). *(Chứng minh hệ thống đo từ hành động thật, không đặt số giả.)*
  2. Bấm các nút lọc ngay trên bảng Danh sách Vụ việc (`Tất cả`, `Chống lừa đảo`, `Chiếm đoạt ATO`, `Lỗi API Logic`, `Tránh khóa oan`, `Chờ duyệt`) và gõ `1903999888777` hoặc `ALT-FPR-004` vào ô tìm kiếm trên header.
  3. Bấm nút **`Ctrl+K`** (hoặc nhấn tổ hợp `Ctrl + K`) để mở Bảng Lệnh Nhanh (*Command Palette*) điều hướng nhanh giữa các vụ việc và phân hệ.
- **Kết quả kỳ vọng:** Danh sách lọc chính xác tức thời; sau khi chạy AI điều tra và duyệt Playbook, các chỉ số KPI tự cập nhật theo số đo thực tế.

### Trường hợp 1.3 — Luồng Cảnh báo Live Feed & Nhập/Xuất Hàng loạt CSV/JSON
- **Thao tác:**
  1. Trên tiêu đề bảng **Danh sách Vụ việc**, bấm **`Live Feed`** để bật/tắt luồng cảnh báo mô phỏng thời gian thực (hoặc gạt công tắc **`Luồng Cảnh báo Live`** ở menu trái).
  2. Bấm **`File mẫu`** để tải tệp `AegisOps_Batch_Template.csv`.
  3. Bấm **`Nhập CSV`** và chọn chính tệp vừa tải (hoặc tệp `.csv`/`.json` tùy chỉnh) → gọi API `POST /api/batch-import`.
  4. Bấm **`Xuất CSV`** để tải báo cáo tổng hợp `AegisOps_Report_Export.csv` (mã hóa UTF-8 BOM mở chuẩn tiếng Việt trên Excel).
- **Kết quả kỳ vọng:** Các vụ việc mới từ tệp CSV được chấm điểm định lượng tự động và xuất hiện ngay trong Danh sách Vụ việc.

### Trường hợp 1.4 — Đối chứng Shadow Mode & Kiến trúc Bảo vệ 4 Tầng
- **Thao tác:** Kéo xuống cuối Dashboard, bấm thanh mở rộng **`Xem thêm cho Giám khảo: Đối chứng Rule Cũ vs AegisOps AI & Kiến trúc Bảo vệ 4 Tầng`**, chuyển qua lại 2 tab **`Đối chứng Shadow Mode`** và **`Kiến trúc 4 Tầng`**.
- **Kết quả kỳ vọng:** Hiển thị rõ vì sao hệ thống rule tĩnh cũ bỏ lọt `ALT-APP-003`/`ALT-BLG-002` hoặc khóa oan `ALT-FPR-004`, trong khi AegisOps xử lý chính xác cả 4 kịch bản.

---

## NHÓM 2 — 4 Kịch bản Thực chiến Gốc (Phủ đủ 3 Chủ đề Cuộc thi)

Vào phân hệ **`Trung tâm Điều tra`** (hoặc bấm **`Điều tra →`** trên từng dòng ở Dashboard):

### Trường hợp 2.1 — `ALT-APP-003` (Chống lừa đảo — APP Fraud Giả danh Công an, `95/100`)
- **Bối cảnh:** Khách hàng Nguyễn Thị Thu Hà tự quét FaceID hợp lệ để chuyển 25.000.000 ₫ (tổng dòng ra 42M) vào tài khoản rác `1903999888777` (`ACC-MULE-903`) trong lúc đang nghe cuộc gọi lạ 19 phút và dán STK từ clipboard; kèm ảnh lệnh bắt giữ giả & tên miền giả `bo-cong-an-xacminh247.vn`.
- **Thao tác:** Bấm **`Bước 1: Chạy AI Điều tra`**.
- **Kết quả kỳ vọng:** Phân loại **`CONFIRMED_APP_SCAM`** (`95/100`), giải thích rõ vì sao dù đã qua FaceID theo QĐ 2345 nhưng tổ hợp tín hiệu `Fan-In = 3 nạn nhân`, `Bipartite Cluster = 0.86`, `in-call coercion` và tên miền typosquatting vẫn xác định là lừa đảo thao túng tâm lý.

### Trường hợp 2.2 — `ALT-ATO-001` (An ninh mạng — Chiếm đoạt Tài khoản & Chia nhỏ Tiền, `99/100`)
- **Bối cảnh:** Kẻ tấn công duy trì phiên đăng nhập trên máy giả lập rooted `DEV-EMU-666` sau khi nạn nhân đã đổi mật khẩu (*Persistent Session Hijack / Refresh Token Replay*) và chia nhỏ 48.000.000 ₫ thành 3 lệnh 16M (`Smurfing Entropy = 0.99`) qua 3 tài khoản Mule.
- **Thao tác:** Chọn **`Vụ #2 (ALT-ATO-001)`** → bấm **`Bước 1: Chạy AI Điều tra`**.
- **Kết quả kỳ vọng:** Phân loại **`CONFIRMED_ATO_MULE`** (`99/100`), đề xuất Playbook thu hồi toàn bộ refresh token, phong tỏa cụm thiết bị `DEV-EMU-666` và chuỗi tài khoản Mule.

### Trường hợp 2.3 — `ALT-BLG-002` (An ninh mạng — Lỗi Logic API Race Condition & Giả mạo HMAC, `99/100`)
- **Bối cảnh:** Tấn công đồng thời `12 request trong 140ms` (*TOCTOU Race Condition*) để nhân bản voucher hoàn tiền 6.000.000 ₫ kết hợp callback thanh toán thiếu chữ ký xác thực HMAC.
- **Thao tác:** Chọn **`Vụ #3 (ALT-BLG-002)`** → bấm **`Bước 1: Chạy AI Điều tra`**.
- **Kết quả kỳ vọng:** Phân loại **`CONFIRMED_LOGIC_ABUSE`** (`99/100`), chỉ đích danh lỗ hổng thiếu khóa Idempotency và vi phạm xác thực Webhook theo TT 50/2024.

### Trường hợp 2.4 — `ALT-FPR-004` (Trợ lý AI lấy con người làm trung tâm — Tránh khóa oan, `14/100`)
- **Bối cảnh:** Khách hàng chuyển 35.000.000 ₫ lúc 23:45 đêm trên iPhone mới sang tài khoản Bệnh viện Đa khoa Quốc tế (`1188999000888` / `ACC-HOSP-800`). Luật cũ nghi ngờ ATO vì khung giờ đêm + thiết bị mới.
- **Thao tác:** Chọn **`Vụ #4 (ALT-FPR-004)`** → bấm **`Bước 1: Chạy AI Điều tra`** → duyệt đóng trạng thái an toàn (`DISMISSED_SAFE`).
- **Kết quả kỳ vọng:** Phân loại **`FALSE_POSITIVE_SAFE`** (`14/100`), hiển thị rõ các yếu tố giảm trừ tin cậy (*Trust Dampeners*: tài khoản đích là bệnh viện uy tín lâu năm, sinh trắc học chính chủ, không có dấu hiệu bị điều khiển từ xa). KPI **`Tránh khóa oan (An toàn)`** trên Dashboard tăng lên `1 cảnh báo`.

---

## NHÓM 3 — Trung tâm Điều tra: Đồ thị BFS, Bằng chứng Gốc, Split-Screen & Copilot

### Trường hợp 3.1 — Đồ thị Truy vết Dòng tiền & Thiết bị (`@xyflow/react`)
- **Thao tác:** Trong `Trung tâm Điều tra`, chuyển các bộ lọc đồ thị **`Tất cả`**, **`Dòng tiền`**, **`Thiết bị / API`**, bấm **`Toàn màn hình`**, và bấm trực tiếp vào bất kỳ ô (node) tài khoản/thiết bị nào trên đồ thị.
- **Kết quả kỳ vọng:** Tự động lọc đúng cạnh liên kết và nhảy trực tiếp tới bằng chứng gốc tương ứng ở bảng chi tiết bên dưới.

### Trường hợp 3.2 — Soi 5 Tab Bằng chứng Gốc & Giải phẫu Link Phishing / `.APK`
- **Thao tác:** Mở lần lượt 5 tab tại khung **Chi tiết Bằng chứng, Thông số Đầu vào & Nhật ký**:
  1. **`Bằng chứng Ảnh / Chat`** — phóng to ảnh chụp tin nhắn lừa đảo mẫu + xem hộp **Bộ giải phẫu Link Phishing, Tên miền Giả mạo & Tệp .APK** (`http://bo-cong-an-xacminh247.vn/lenh-tam-giu`).
  2. **`Hồ sơ Đầu vào (4 Phần)`** — xem đầy đủ dữ liệu đầu vào chuẩn hóa, có thể bấm **`Tùy chỉnh Thông số Vụ này`** để sửa trực tiếp và tính lại điểm.
  3. **`Giao dịch & API`**, **`Phiên Đăng nhập`**, **`Nhật ký`**.
- **Kết quả kỳ vọng:** Mọi mã trích dẫn (`EVD-103`, `TXN-9011`, `DEV-EMU-666`, `LOG-AUTH-304`) trong báo cáo AI đều bấm được để đối chiếu thẳng về bằng chứng gốc.

### Trường hợp 3.3 — Xem Song song Ví (*Split-Screen*) & Gom nhóm Chiến dịch Đa vụ án (*Batch Triage*)
- **Thao tác:**
  1. Bật công tắc **`Xem Song song Ví`** ở thanh menu dọc bên trái để hiển thị đồng thời Trung tâm Điều tra và Ví MoMo cạnh nhau.
  2. Bấm nút **`Gom nhóm AI`** trên hàng danh sách vụ việc → hệ thống tự phát hiện các vụ án liên kết chung cụm thiết bị/Mule (`ALT-APP-003` & `ALT-ATO-001` chung `ACC-MULE-903` / `DEV-EMU-666`).
  3. Ở vai trò `L2 Checker`, bấm **`Thực thi Gom nhóm 1-Chạm`** để xử lý đồng loạt cả chiến dịch.
- **Kết quả kỳ vọng:** Hiện thông báo **`Hoàn tất Xử lý Gom nhóm 1-Chạm`** và kích hoạt lá chắn hàng loạt cho toàn cụm gian lận.

### Trường hợp 3.4 — Trợ lý AI Copilot, Huy hiệu Nguồn Phân tích & Kiểm định Trích dẫn
- **Thao tác:**
  1. Quan sát **`ai-source-badge`** ở cột phải: hiển thị rõ đang chạy **`Gemini 3.5 Flash-Lite (Live)`**, **`Fallback Model`** hay **`Chế độ Dự phòng Định lượng`** (không bao giờ che giấu nguồn phân tích).
  2. Chuyển qua lại 3 tab con trong panel Copilot: **Đóng góp Rủi ro (Attribution)**, **5 Công cụ Định lượng**, và **Hỏi đáp Copilot**.
  3. Bấm các câu hỏi gợi ý theo ngữ cảnh từng kịch bản hoặc gõ câu hỏi tiếng Việt bất kỳ (ví dụ: *"Nếu khách đã quét FaceID, bằng chứng nào khẳng định đây vẫn là lừa đảo?"*).
- **Kết quả kỳ vọng:** Copilot trả lời bằng tiếng Việt bám sát bằng chứng gốc của đúng vụ án đang chọn; mọi mã trích dẫn không tồn tại đều bị `Citation Validator` loại bỏ tự động.

---

## NHÓM 4 — Quản trị Ngân hàng: Kiểm soát Kép Maker–Checker & Adaptive HITL Memory

### Trường hợp 4.1 — Kiểm soát Kép Phân quyền (`L1 Maker` vs `L2 Checker` vs `End-User`)
- **Thao tác:**
  1. Ở thanh menu trái, đổi mục **`Chế độ Giả lập Vai trò Demo (Maker-Checker)`** sang **`Chuyên viên L1 (Maker)`**.
  2. Tại `ALT-APP-003` (sau khi chạy AI Điều tra), quan sát nút duyệt đổi thành **`B3: Trình Playbook lên L2 (Maker)`** → bấm để chuyển vụ việc sang trạng thái **`Chờ L2 phê duyệt`**.
  3. Thử bấm **`Gom nhóm AI`** khi đang ở vai trò L1 → hệ thống khóa nút thực thi và hiện cảnh báo **`Chỉ Quản lý Rủi ro L2 (Checker) mới được thực thi Gom nhóm 1-Chạm`**.
  4. Đổi vai trò lại thành **`Quản lý Rủi ro L2 (Checker)`** → nút **`L2 Phê duyệt & Bật Lá chắn`** mở khóa để hoàn tất phê duyệt.
  5. Thử đổi sang **`Khách hàng Ví (End-User)`** → hệ thống tự chuyển sang màn hình Ví & Lá chắn Người dùng.
- **Kết quả kỳ vọng:** Cưỡng chế đúng nguyên tắc 4 mắt (*Four-Eyes Principle*) trên cả giao diện lẫn máy chủ (`POST /api/playbook`).

### Trường hợp 4.2 — Bộ nhớ Phản hồi Thích ứng (*Adaptive HITL Feedback Lifecycle*)
- **Thao tác:**
  1. Trong `Trung tâm Điều tra`, mở **`Vụ #4 (ALT-FPR-004)`** (hoặc bất kỳ vụ nào) → bấm **`Bộ nhớ Phản hồi HITL`**.
  2. Chọn phạm vi áp dụng (ví dụ: **`RECIPIENT_PATTERN`**), nhập lý do chuyên viên (ví dụ: *"Xác nhận tài khoản bệnh viện đối tác an toàn"*) → bấm **`Lưu Bộ nhớ HITL An toàn`**.
  3. Quan sát trạng thái **`APPROVED_ACTIVE`**, dòng giải thích **`Adaptive HITL Memory: Điểm gốc...`** và huy hiệu **`Adaptive HITL SAFE`**.
  4. Bấm **`Thu hồi (Revoke)`** để thu hồi quy tắc phản hồi.
- **Kết quả kỳ vọng:** Trạng thái chuyển sang **`REVOKED`**, huy hiệu điều chỉnh biến mất ngay lập tức; bộ nhớ HITL luôn có thời hạn (TTL), giải thích minh bạch và **không bao giờ được phép vượt qua luật chặn cứng** với tín hiệu tấn công nghiêm trọng.

---

## NHÓM 5 — Nhập Hồ sơ Kiểm thử Động (*Case Builder 4 Phần & Live Sandbox*)

Vào phân hệ **`Nhập Hồ sơ Kiểm thử`** ở thanh menu trái:

### Trường hợp 5.1 — 4 Mẫu Chuẩn 4 Phần & Xem trước Điểm Động (*Debounced Live Preview*)
- **Thao tác:** Bấm lần lượt 4 mẫu có sẵn ở đầu biểu mẫu:
  - **`Mẫu 1 • Giao dịch Hợp lệ (An toàn)`** (`PRESET-SAFE`, ~`14/100`)
  - **`Mẫu 2 • Lừa đảo Thao túng Tâm lý (APP Fraud)`** (`PRESET-APP-FRAUD`, ~`95/100`)
  - **`Mẫu 3 • Chiếm đoạt Tài khoản & Chia nhỏ Tiền (ATO)`** (`PRESET-CYBER-ATO`, ~`97/100`)
  - **`Mẫu 4 • Tấn công Lỗ hổng API (Race Condition)`** (`PRESET-RACE-LOGIC`, ~`93/100`)
  - Thử thay đổi bất kỳ thông số nào (số tiền, tuổi tài khoản đích, bật/tắt cuộc gọi lạ, đổi chữ ký Webhook HMAC thành không hợp lệ) và quan sát bảng **Dự báo Định lượng Tức thời** cập nhật sau `120ms`.
- **Kết quả kỳ vọng:** Điểm rủi ro, phân loại và giải thích thay đổi trung thực theo đúng dữ liệu nhập.

### Trường hợp 5.2 — 3 Ảnh Bằng chứng Mẫu Trực quan & Bóc tách Thực thể Tự động
- **Thao tác:** Chọn 1 trong 3 ảnh mẫu trong thư viện **Sandbox Visual Gallery**:
  - **`Ảnh Mẫu 1: Giả Shipper Hoàn tiền`** (`1903777666555` — `18.500.000 ₫`)
  - **`Ảnh Mẫu 2: Bill Giả đòi tiền thừa`** (`1903666555444` — `40.000.000 ₫`)
  - **`Ảnh Mẫu 3: Tuyển CTV Hoa hồng 30%`** (`1903555444333` — `22.000.000 ₫`)
  - Bấm **`Tạo Hồ sơ, Dựng Đồ thị & Chạy Điều tra Ngay`**.
- **Kết quả kỳ vọng:** Hệ thống tạo mã vụ việc động **`ALT-SND-xxxx`**, dựng đồ thị BFS mới, gọi AI phân tích đa phương thức, và khi L2 duyệt Playbook sẽ **chặn chính số tài khoản vừa tạo** ở Ví MoMo!

### Trường hợp 5.3 — Giám khảo Tự nhập Văn bản Lừa đảo hoặc Tải Ảnh từ Máy cá nhân
- **Thao tác:** Tự dán một đoạn tin nhắn mô phỏng chứa số tài khoản + số tiền (ví dụ: *"Anh chuyển 28.000.000 đ vào STK 1903888999000 NGUYEN VAN B để xác minh hoàn thuế"*), bấm nút tự bóc tách thực thể hoặc tải lên ảnh chụp mẫu (`.png`/`.jpg`/`.webp`, tối đa `3.0 MB`), rồi bấm tạo hồ sơ.
- **Kết quả kỳ vọng:** Tự trích xuất STK/số tiền, dựng hồ sơ điều tra mới, lưu bền vững vào phiên trên Neon PostgreSQL và có thể kiểm chứng chặn ngay trên Ví.

---

## NHÓM 6 — Ví MoMo Mô phỏng, Lá chắn Thời gian thực, Clawback & VietQR

Vào phân hệ **`Ví & Lá chắn Người dùng`** (hoặc bấm nút **`Ví MoMo`** ở thanh header):

### Trường hợp 6.1 — Cảnh báo Làm nguội Tâm lý & Tạm giữ `HELD` (Trước khi L2 duyệt)
- **Thao tác:** Khi **chưa** bật lá chắn cho `ALT-APP-003`, giữ nguyên số tài khoản `1903999888777`, số tiền `18.000.000 ₫`, nội dung *"Chuyen tien xac minh tai san theo yeu cau cong an"*, bấm **`Xác nhận Chuyển`**.
- **Kết quả kỳ vọng:** Hệ thống hiển thị **`CẢNH BÁO LÀM NGUỘI TÂM LÝ`** + **Thẻ Gỡ bùa Tâm lý**, chuyển trạng thái giao dịch sang **`HELD` (Tạm giữ)** và **số dư `45.000.000 ₫` KHÔNG bị trừ sớm**. Nạn nhân có thể bấm nút tự hủy giải cứu (*Self-Rescue*) hoặc báo cáo lên trung tâm Risk.

### Trường hợp 6.2 — Chặn cứng Đèn Đỏ `BLOCKED` (Sau khi L2 duyệt Playbook)
- **Thao tác:** Duyệt Playbook L2 cho `ALT-APP-003` trước, sau đó mở Ví MoMo và bấm **`Xác nhận Chuyển`** tới `1903999888777`.
- **Kết quả kỳ vọng:** Đèn Tín nhiệm chuyển sang **Đỏ (Nguy hiểm)**, giao dịch bị chặn cứng **`Giao dịch bị chặn bởi Lá chắn Aegis Shield`** (`BLOCKED`), số dư **`45.000.000 ₫` giữ nguyên tuyệt đối**.

### Trường hợp 6.3 — Giao dịch Hợp lệ `SETTLED` & Trừ Số dư trên Sổ cái Hợp nhất
- **Thao tác:** Nhập STK người nhận **`1188999000888`** (Bệnh viện Đa khoa Quốc tế — `ACC-HOSP-800`), số tiền **`5000000`** (`5.000.000 ₫`), lời nhắn *"Thanh toan hoa don benh vien"*, bấm **`Xác nhận Chuyển 5.000.000 ₫`**.
- **Kết quả kỳ vọng:** Đèn Xanh — **`Giao dịch hợp lệ — Cho phép thực hiện`**, số dư trừ trực tiếp **`45.000.000 ₫ → 40.000.000 ₫`**, sinh mã giao dịch thật trong phiên **`TXN-WAL-...`** và hiện nút **`Đối soát ở Loa Tiểu thương`** để kiểm chứng ngay ở Nhóm 7.

### Trường hợp 6.4 — Hoàn tiền 1-Chạm Giao dịch Đã Hạch toán (*1-Click Clawback & Idempotency*)
- **Thao tác:** Quay lại `Trung tâm Điều tra` → `ALT-APP-003` (đã được L2 duyệt) → bấm nút **`Thu hồi & Hoàn trả GD Đã Hạch toán (TXN-9011...)`**.
- **Kết quả kỳ vọng:** Đảo sổ thành công **`25.000.000 ₫`** từ `ACC-MULE-903` về ví nạn nhân (`ACC-USR-103`), hiện thông báo **`Đã Thu hồi & Hoàn 25.000.000 ₫ về Ví Nạn nhân`**, nút Clawback tự ẩn để **chống hoàn tiền trùng 2 lần**, và khi mở lại Ví MoMo số dư tăng đúng **`+25.000.000 ₫`** (từ `45M → 70M` nếu chưa chuyển khoản khác).

### Trường hợp 6.5 — Quét & Giải mã VietQR EMVCo TLV Cục bộ
- **Thao tác:** Trong giao diện Ví MoMo, bấm các nút thử mẫu VietQR:
  - **`QR-SPOOF-GHN`:** Hiển thị nhãn giả *CỔNG HOÀN TIỀN GIAO HÀNG NHANH (GHN EXPRESS)* nhưng bộ giải mã EMVCo TLV cục bộ bóc tách ra STK nhận thực tế là tài khoản Mule `1903999888777` và cảnh báo sai lệch tên pháp lý NAPAS.
  - **`QR-HOSPITAL-SAFE`:** Khớp tên pháp lý Bệnh viện Đa khoa Quốc tế TP.HCM.
  - Hoặc mở mục **Tự nhập TLV** và dán trực tiếp chuỗi EMVCo TLV thô để xem hệ thống giải mã từng trường (`Tag 38`, `Tag 54`, `Tag 62`, `CRC Tag 63`).
- **Kết quả kỳ vọng:** Giải mã cục bộ chính xác và cảnh báo tức thời khi mã QR ngụy trang thương hiệu uy tín.

---

## NHÓM 7 — Chế độ Tiểu thương: Đối soát Sổ cái 5 Case (A–E), Loa Soundbox & Vision OCR

Trong phân hệ **`Ví & Lá chắn Người dùng`**, chuyển tab sang **`Tiểu thương (Bill & Loa)`**:

### Trường hợp 7.1–7.5 — Kiểm chứng đủ 5 Trường hợp Đối soát Bill Chuyển khoản (`POST /api/merchant/verify`)
| Case | Nút bấm / Thao tác | Dữ liệu kiểm thử | Kết quả Sổ cái & Loa Soundbox kỳ vọng |
|---|---|---|---|
| **Case A** | Bấm **`Đối soát ở Loa Tiểu thương`** ngay sau khi chuyển `5.000.000 ₫` ở Case 6.3 (hoặc nhập `TXN-MERCH-OK`, `4.850.000 ₫`) | GD có thật, trạng thái `SETTLED`, đúng tiền, đúng STK nhận | **`GIAO DỊCH THẬT — ĐÃ NHẬN TIỀN ĐỦ VÀO SỔ CÁI`** + Loa Soundbox đọc xác nhận |
| **Case B** | Bấm **`Case B: Bill Sửa Số Tiền`** | Bill ghi `15.000.000 ₫` nhưng Sổ cái chỉ nhận `1.000 ₫` (`TXN-MERCH-1K`) | **`CẢNH BÁO BILL SỬA SỐ TIỀN`** (`AMOUNT_MISMATCH`) |
| **Case C** | Bấm **`Case C: Bill Không Tồn Tại`** | Mã giao dịch không tồn tại trên Sổ cái | **`KHÔNG TÌM THẤY GIAO DỊCH — BILL KHÔNG CÓ TRÊN SỔ CÁI`** |
| **Case D** | Bấm **`Case D: Giao dịch Đã Bị Chặn`** | Mã giao dịch ở trạng thái `BLOCKED` / chưa hạch toán | **`GIAO DỊCH ĐÃ BỊ CHẶN – TIỀN KHÔNG VÀO SỔ CÁI`** |
| **Case E** | Bấm **`Case E: Sai Tài Khoản Tiểu Thương Nhận`** | `TXN-MERCH-OK` (`4.850.000 ₫`) nhưng tiền vào tài khoản khác (`ACC-USR-104`) | **`KHÔNG KHỚP NGƯỜI NHẬN — BILL CHUYỂN SANG TÀI KHOẢN KHÁC`** |

### Trường hợp 7.6 — AI Vision Quét Ảnh Bill & Chốt chặn Bảo mật Tệp `.SVG` (`POST /api/merchant/vision`)
- **Thao tác:**
  1. Ở khung **`AI Vision Quét Ảnh Bill`**, thử tải lên một tệp `.svg` giả mạo → hệ thống từ chối an toàn ngay lập tức với thông báo **`Chỉ hỗ trợ ảnh chụp màn hình PNG, JPEG hoặc WebP`**.
  2. Tải lên một ảnh chụp hóa đơn mô phỏng (`.png`/`.jpg`/`.webp`, ≤ `3.0 MB`) → quan sát 2 khung kết quả tách biệt: **`1. Thông tin AI OCR Trích xuất`** và **`2. Kết luận Đối soát Sổ cái Gốc`** (`merchant-vision-verdict`).
- **Kết quả kỳ vọng:** Ảnh gốc không bị lưu vào `localStorage`, AI OCR không có quyền tự xác nhận tiền vào khi sổ cái không khớp, và ảnh bị cắt/mờ/độ tin cậy thấp sẽ tự định tuyến sang **`NEEDS_MANUAL_REVIEW`**.

---

## NHÓM 8 — Hồ sơ Pháp lý NHNN, In PDF, Bản tin SIMO & Nhật ký Audit

Vào phân hệ **`Pháp lý & Nhật ký Audit`** ở thanh menu trái:

### Trường hợp 8.1 — Đối chiếu Pháp lý Trung thực theo 4 Văn bản Quy phạm
- **Thao tác:** Chọn lần lượt từng vụ việc trong hộp chọn hồ sơ (`ALT-APP-003`, `ALT-ATO-001`, `ALT-BLG-002`, `ALT-FPR-004`).
- **Kết quả kỳ vọng:** Hiển thị bản tóm tắt có cấu trúc và 3 thẻ đối chiếu pháp lý:
  - **Quyết định 2345/QĐ-NHNN** (`REQUIREMENT_MAPPED`, `VERIFIED`)
  - **Thông tư 50/2024/TT-NHNN sửa đổi bổ sung bởi Thông tư 77/2025/TT-NHNN** (`REQUIREMENT_MAPPED`, minh bạch **`CERTIFICATION_NOT_VERIFIED`** cho tín hiệu PAD ISO 30107 mô phỏng)
  - **Luật Bảo vệ Dữ liệu Cá nhân 91/2025/QH15 & Nghị định 356/2025/NĐ-CP** (`LEGAL_REVIEW_REQUIRED`)

### Trường hợp 8.2 — Mở & Xuất Biên bản PDF (`ComplianceReportModal` + Print CSS)
- **Thao tác:** Bấm **`Mở & Xuất PDF`** (hoặc nút **`Biên bản PDF`** trong Trung tâm Điều tra), sau đó nhấn `Ctrl + P` để xem bản xem trước in.
- **Kết quả kỳ vọng:** Khi in, giao diện tự động chuyển sang nền trắng mực đậm (`.printable-dossier-card` = `#FFFFFF`), ẩn toàn bộ nút điều khiển `.no-print`, giữ đầy đủ nhãn `SIMULATED` và trạng thái pháp lý trung thực.

### Trường hợp 8.3 — Bản tin Đồng bộ SIMO Mô phỏng & Nhật ký Kiểm toán (*Audit Trail*)
- **Thao tác:**
  1. Xem khung JSON **Bản tin Đồng bộ SIMO Mô phỏng** (đã giả danh hóa bằng SHA-256 / server HMAC-SHA-256) và bấm **`Gửi bản tin SIMO (Mô phỏng)`**.
  2. Chuyển sang cột **Nhật ký Kiểm toán Hệ thống** bên phải và bấm các bộ lọc **`Tất cả`**, **`AI Agent`**, **`Chuyên viên`**, **`Lá chắn Ví`**.
- **Kết quả kỳ vọng:** Sinh mã biên nhận SIMO cục bộ kèm cảnh báo rõ `SIMULATED — Chưa kết nối mạng NHNN/A05 thực tế`; toàn bộ hành động đã thực hiện trong phiên đều được ghi vết kèm mốc thời gian.

---

## NHÓM 9 — Kiểm chứng Kỹ thuật, Bảo mật Cloud & Tự động hóa (Dành cho Giám khảo Kỹ thuật)

### Trường hợp 9.1 — Kiểm tra Trạng thái Hạ tầng Trực tuyến (Readiness & Liveness)
- Mở trực tiếp trên trình duyệt hoặc chạy `curl`:
  - `GET https://aegisops-momo-contest-2026.netlify.app/api/health?probe=live` → `HTTP 200` (`status: "ok"`, `probe: "liveness"`).
  - `GET https://aegisops-momo-contest-2026.netlify.app/api/health` → `HTTP 200`, `deploymentReadinessTier: "PRODUCTION_SHARED_INFRA_READY"`, `aiMode: "AI_LIVE"`, `aiCircuit.state: "CLOSED"`, toàn bộ `7/7` dependency flags = `true` (`secretsReady`, `persistenceReady`, `rateLimiterReady`, `quotaScopeReady`, `globalQuotaConfigReady`, `fallbackModelReady`, `demoPersonaGuardReady`).

### Trường hợp 9.2 — Cô lập Đa phiên & Lưu trữ Bền vững trên Neon PostgreSQL
- **Thao tác:**
  1. Ở cửa sổ trình duyệt A, duyệt Playbook `ALT-APP-003` và tạo 1 hồ sơ Sandbox mới → bấm `F5` tải lại trang.
  2. Mở cửa sổ Ẩn danh B (`Ctrl + Shift + N`) vào cùng đường dẫn.
- **Kết quả kỳ vọng:** Trình duyệt A **giữ nguyên trạng thái đã duyệt và vụ việc mới** (lưu bền vững trên Neon PostgreSQL `18.7`); trình duyệt B khởi tạo một **phiên hoàn toàn độc lập** (`ALT-APP-003` vẫn ở trạng thái `Chờ xử lý`, `0` lá chắn), chứng minh cô lập đa phiên tuyệt đối.

### Trường hợp 9.3 — Kiểm chứng Chốt chặn Bảo mật API & Chống Giả mạo Proxy IP
- `GET /api/workspace` (không có cookie phiên ký HMAC): trả **`401 UNAUTHORIZED`**; cố tình gửi `x-workspace-session` khác phiên của mình bị chặn **`401` / `403`**.
- `GET /api/internal/cleanup` (không có hoặc sai `Authorization: Bearer <CRON_SECRET>`): trả **`401 UNAUTHORIZED`**. *(Lịch chạy tự động hàng ngày lúc `03:00 UTC` / `10:00` giờ Việt Nam qua `cron-job.org` đã được xác minh trực tiếp trả `200 OK` đối với Neon PostgreSQL).*
- `GET /api/health?diagnostics=internal` (không có mã nội bộ): trả `403`, sau `15` yêu cầu/phút sẽ bị Upstash Redis chặn **`429 DIAGNOSTICS_RATE_LIMIT_EXCEEDED`** và **không thể vượt qua** bằng cách giả mạo header `x-real-ip` hoặc `x-forwarded-for` (vì máy chủ trên Netlify chỉ tin cậy duy nhất header `x-nf-client-connection-ip`).

### Trường hợp 9.4 — Kiểm chứng Responsive Đa thiết bị & Bộ Kiểm thử Tự động 170 Bài Test
- **Responsive:** Thu phóng trình duyệt ở 6 kích thước chuẩn (`1440×900`, `1366×768`, `1024×768`, `768×1024`, `390×844`, `375×812`) trên cả Dashboard, Trung tâm Điều tra và Pháp lý — **18/18 tổ hợp đạt `0px` tràn ngang**, thanh điều hướng tự chuyển sang dạng gọn trên di động.
- **Bộ kiểm thử tự động trong kho mã nguồn (`npm test` & `npm run test:e2e`):**
  - **20 file / 159 bài Unit, Security & Red-Team Tests (Vitest):** kiểm chứng Forensics, Prompt Injection (8 vector), giới hạn payload nhị phân `3,000,000` bytes (HTTP `413`), Upstash `/multi-exec` atomicity, Neon TLS `verify-full`, Netlify proxy IP hardening, Clawback idempotency, và chuỗi dự phòng 3 tầng Gemini.
  - **11 kịch bản Playwright E2E Golden Paths:** tự động hóa trọn vẹn từ Scenario 1 đến Scenario 11 trên trình duyệt Chromium thực tế.
