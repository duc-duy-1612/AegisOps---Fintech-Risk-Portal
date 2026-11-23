/**
 * Pre-bundled Multimodal Evidence Gallery for Judge's 1-Click Live Sandbox Testing
 * Allows judges without local scam screenshots on their laptop to test Multimodal Vision with 1 click.
 */

export interface SandboxVisualSample {
  id: string;
  badgeVi: string;
  title: string;
  recipientAccountNumber: string;
  recipientOwnerName: string;
  amountVnd: number;
  transcript: string;
  imageDataUrl: string;
}

const SHIPPER_SCAM_SVG = `data:image/svg+xml;utf8,${encodeURIComponent(`
<svg xmlns="http://www.w3.org/2000/svg" width="520" height="270" viewBox="0 0 520 270">
  <rect width="520" height="270" rx="14" fill="#0F172A" stroke="#334155" stroke-width="2"/>
  <rect width="520" height="42" rx="14" fill="#1E293B"/>
  <circle cx="22" cy="21" r="7" fill="#F59E0B"/>
  <text x="38" y="26" fill="#F8FAFC" font-family="sans-serif" font-size="13" font-weight="bold">SHIPPER GIAO HÀNG NHANH (TIN NHẮN LỪA ĐẢO)</text>
  <rect x="16" y="54" width="440" height="68" rx="10" fill="#1E293B" stroke="#F59E0B"/>
  <text x="28" y="76" fill="#FBBF24" font-family="sans-serif" font-size="12" font-weight="bold">Đơn hàng #GHN-8821 giao thất bại — Kích hoạt Hoàn tiền Cọc</text>
  <text x="28" y="96" fill="#F8FAFC" font-family="sans-serif" font-size="12">Anh/chị bấm link: http://hoantien-giaohang247.vn và chuyển khoản xác thực</text>
  <text x="28" y="112" fill="#F8FAFC" font-family="sans-serif" font-size="12">để hệ thống hủy trừ phí thẻ hội viên 3.500.000đ/tháng tự động!</text>
  <rect x="16" y="132" width="440" height="64" rx="10" fill="#31102F" stroke="#EF4444" stroke-width="1.5"/>
  <text x="28" y="154" fill="#FCA5A5" font-family="monospace" font-size="13" font-weight="bold">STK XÁC THỰC: 1903777666555 • CHỦ TK: LE VAN TUNG</text>
  <text x="28" y="176" fill="#F8FAFC" font-family="monospace" font-size="12">SỐ TIỀN YÊU CẦU: 18.500.000 VNĐ (Hoàn lại sau 3 phút)</text>
  <rect x="180" y="208" width="320" height="46" rx="10" fill="#064E3B"/>
  <text x="196" y="235" fill="#A7F3D0" font-family="sans-serif" font-size="12">Ủa sao hoàn tiền mà em phải chuyển 18.500.000đ vào STK này ạ?</text>
</svg>
`)}`;

const FAKE_BILL_SCAM_SVG = `data:image/svg+xml;utf8,${encodeURIComponent(`
<svg xmlns="http://www.w3.org/2000/svg" width="520" height="270" viewBox="0 0 520 270">
  <rect width="520" height="270" rx="14" fill="#0F172A" stroke="#334155" stroke-width="2"/>
  <rect width="520" height="42" rx="14" fill="#1E293B"/>
  <circle cx="22" cy="21" r="7" fill="#EF4444"/>
  <text x="38" y="26" fill="#F8FAFC" font-family="sans-serif" font-size="13" font-weight="bold">BIÊN LAI CHUYỂN KHOẢN GIẢ &amp; KỊCH BẢN "CHUYỂN NHẦM"</text>
  <rect x="16" y="54" width="215" height="198" rx="10" fill="#1E293B" stroke="#EF4444" stroke-dasharray="4 2"/>
  <text x="28" y="78" fill="#FCA5A5" font-family="monospace" font-size="11" font-weight="bold">[ẢNH BILL PHOTOSHOP]</text>
  <text x="28" y="102" fill="#F8FAFC" font-family="monospace" font-size="13" font-weight="bold">+ 45.000.000 VNĐ</text>
  <text x="28" y="124" fill="#94A3B8" font-family="monospace" font-size="11">Mã GD: FT26999FAKE00</text>
  <text x="28" y="144" fill="#94A3B8" font-family="monospace" font-size="11">Trạng thái: Đang xử lý</text>
  <text x="28" y="174" fill="#FBBF24" font-family="sans-serif" font-size="11">• Lệch font chữ số tiền</text>
  <text x="28" y="194" fill="#FBBF24" font-family="sans-serif" font-size="11">• Tiền chưa hề vào sổ cái</text>
  <rect x="245" y="54" width="258" height="198" rx="10" fill="#31102F" stroke="#F59E0B"/>
  <text x="258" y="80" fill="#FBBF24" font-family="sans-serif" font-size="12" font-weight="bold">Tin nhắn hối thúc chủ shop:</text>
  <text x="258" y="104" fill="#F8FAFC" font-family="sans-serif" font-size="12">"Shop ơi đơn em có 5 triệu mà em</text>
  <text x="258" y="122" fill="#F8FAFC" font-family="sans-serif" font-size="12">bấm nhầm thành 45 triệu rồi! Liên</text>
  <text x="258" y="140" fill="#F8FAFC" font-family="sans-serif" font-size="12">ngân hàng hơi trễ, shop chuyển</text>
  <text x="258" y="158" fill="#F8FAFC" font-family="sans-serif" font-size="12">trả gấp giúp em 40.000.000đ về:</text>
  <text x="258" y="186" fill="#FCA5A5" font-family="monospace" font-size="12" font-weight="bold">STK: 1903666555444</text>
  <text x="258" y="206" fill="#FCA5A5" font-family="monospace" font-size="12" font-weight="bold">CHỦ TK: PHAM VAN DUC"</text>
</svg>
`)}`;

const CTV_TASK_SCAM_SVG = `data:image/svg+xml;utf8,${encodeURIComponent(`
<svg xmlns="http://www.w3.org/2000/svg" width="520" height="270" viewBox="0 0 520 270">
  <rect width="520" height="270" rx="14" fill="#0F172A" stroke="#334155" stroke-width="2"/>
  <rect width="520" height="42" rx="14" fill="#1E293B"/>
  <circle cx="22" cy="21" r="7" fill="#8B5CF6"/>
  <text x="38" y="26" fill="#F8FAFC" font-family="sans-serif" font-size="13" font-weight="bold">NHÓM VIP CỘNG TÁC VIÊN LÀM NHIỆM VỤ HOA HỒNG 30%</text>
  <rect x="16" y="56" width="485" height="90" rx="10" fill="#1E293B" stroke="#8B5CF6"/>
  <text x="28" y="80" fill="#C4B5FD" font-family="sans-serif" font-size="12" font-weight="bold">[ĐIỀU PHỐI VIÊN NHIỆM VỤ VIP #3]</text>
  <text x="28" y="102" fill="#F8FAFC" font-family="sans-serif" font-size="12">Chúc mừng bạn đã hoàn thành đơn 1! Tuy nhiên hệ thống báo tài khoản</text>
  <text x="28" y="120" fill="#F8FAFC" font-family="sans-serif" font-size="12">bị đóng băng điểm tín nhiệm. Cần nạp lệnh Gỡ Băng trong 15 phút!</text>
  <rect x="16" y="158" width="485" height="92" rx="10" fill="#31102F" stroke="#F59E0B" stroke-width="1.5"/>
  <text x="28" y="182" fill="#FBBF24" font-family="monospace" font-size="13" font-weight="bold">STK NHẬN TIỀN NHIỆM VỤ: 1903555444333 (PHAM THI HUONG)</text>
  <text x="28" y="204" fill="#F8FAFC" font-family="monospace" font-size="12">SỐ TIỀN NẠP GỠ BĂNG: 22.000.000 VNĐ → Nhận về 28.600.000 VNĐ</text>
  <text x="28" y="226" fill="#FCA5A5" font-family="sans-serif" font-size="11">Lưu ý: Giữ bí mật tuyệt đối, quá 15 phút mất toàn bộ tiền gốc!</text>
</svg>
`)}`;

export const SANDBOX_VISUAL_GALLERY: SandboxVisualSample[] = [
  {
    id: 'SAMPLE-SHIPPER',
    badgeVi: 'Ảnh Mẫu 1: Giả Shipper Hoàn tiền',
    title: '[Live Sandbox] Giả danh Shipper gửi link hoàn tiền 18.500.000 ₫',
    recipientAccountNumber: '1903777666555',
    recipientOwnerName: 'LE VAN TUNG',
    amountVnd: 18_500_000,
    transcript:
      'Anh ơi đơn hàng giao thất bại, anh bấm vào link http://hoantien-giaohang247.vn và chuyển khoản xác thực 18.500.000 VNĐ vào STK 1903777666555 chủ TK LE VAN TUNG trong 10 phút để hệ thống hoàn lại tiền cọc và hủy trừ phí hội viên nhé!',
    imageDataUrl: SHIPPER_SCAM_SVG,
  },
  {
    id: 'SAMPLE-FAKE-BILL',
    badgeVi: 'Ảnh Mẫu 2: Bill Giả đòi tiền thừa',
    title: '[Live Sandbox] Gửi Bill chuyển khoản giả 45M đòi hoàn tiền thừa 40M',
    recipientAccountNumber: '1903666555444',
    recipientOwnerName: 'PHAM VAN DUC',
    amountVnd: 40_000_000,
    transcript:
      'Shop ơi đơn em có 5 triệu mà em bấm nhầm thành 45.000.000 VNĐ rồi (em gửi ảnh bill đính kèm). Liên ngân hàng hơi trễ, shop chuyển trả gấp giúp em 40.000.000 VNĐ về STK 1903666555444 chủ TK PHAM VAN DUC ngay giúp em nhé!',
    imageDataUrl: FAKE_BILL_SCAM_SVG,
  },
  {
    id: 'SAMPLE-CTV',
    badgeVi: 'Ảnh Mẫu 3: Tuyển CTV Hoa hồng 30%',
    title: '[Live Sandbox] Lừa đảo Cộng tác viên nạp 22.000.000 ₫ gỡ băng nhiệm vụ',
    recipientAccountNumber: '1903555444333',
    recipientOwnerName: 'PHAM THI HUONG',
    amountVnd: 22_000_000,
    transcript:
      'Chúc mừng bạn hoàn thành nhiệm vụ 1! Để gỡ đóng băng điểm tín nhiệm và rút cả gốc lẫn 30% hoa hồng, vui lòng chuyển gấp 22.000.000 VNĐ vào STK 1903555444333 tên PHAM THI HUONG trong 15 phút, giữ bí mật tuyệt đối.',
    imageDataUrl: CTV_TASK_SCAM_SVG,
  },
];
