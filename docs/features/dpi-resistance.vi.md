---
description: "Cách Teleproxy đánh bại kiểm tra gói tin sâu. Phương pháp phát hiện TSPU/ASBI và các biện pháp đối phó phía máy chủ."
---

# Kháng DPI

Teleproxy bao gồm nhiều lớp phòng thủ chống lại hệ thống Kiểm tra Gói tin Sâu (DPI) nhằm phát hiện và chặn lưu lượng MTProxy.

## Bối cảnh mối đe dọa hiện tại

Tính đến tháng 4 năm 2026, các hệ thống DPI của Nga (TSPU/ASBI) phân loại MTProxy fake-TLS là một giao thức riêng biệt ("TELEGRAM_TLS"). Việc phát hiện chủ yếu dựa vào **dấu vân tay TLS phía client** — ClientHello của ứng dụng Telegram có các đặc điểm JA3/JA4 dễ nhận biết mà DPI so khớp với các chữ ký đã biết.

Các quan sát chính:

- **Nhà mạng di động** (MTS, Megafon, Beeline, T2, Yota) bị ảnh hưởng nhiều hơn ISP gia đình — mức độ triển khai TSPU khác nhau theo nhà cung cấp
- **Kết nối VPN vượt qua** cả heuristic DPI và chặn ở cấp IP
- **Công cụ phân mảnh gói tin phía client** (zapret, GoodbyeDPI) khôi phục kết nối, xác nhận rằng DPI so khớp mẫu trên các đoạn TCP nguyên vẹn
- Telegram Desktop [đã cập nhật dấu vân tay TLS](https://github.com/telegramdesktop/tdesktop/pull/30513) để sửa các artifact có thể phát hiện được; client di động có thể chậm hơn

## Teleproxy làm gì (phía server)

### Ngụy trang Fake-TLS

Toàn bộ lưu lượng được bọc trong bản ghi TLS 1.3 với ClientHello profile Chrome. Xem [Fake-TLS](fake-tls.md) để thiết lập.

### TLS backend tùy chỉnh (kháng thăm dò chủ động)

Hệ thống DPI chủ động thăm dò các proxy bị nghi ngờ. Khi chạy với TLS backend thực (nginx có chứng chỉ hợp lệ), mọi kết nối không hợp lệ — sai secret, timestamp hết hạn, thăm dò DPI — đều được chuyển tiếp đến website thực. Thăm dò sẽ thấy một server HTTPS hợp lệ.

Đây là biện pháp phía server hiệu quả nhất. Xem [Fake-TLS: TLS Backend Tùy chỉnh](fake-tls.md#custom-tls-backend-tcp-splitting).

### Thay đổi kích thước bản ghi động (DRS)

Kích thước bản ghi TLS tuân theo mẫu tăng dần phù hợp với web server thực (Cloudflare, Caddy): kích thước MTU trong giai đoạn khởi động chậm, tăng dần đến tối đa. Nhiễu ngẫu nhiên được thêm vào mỗi bản ghi. Điều này đánh bại phân tích thống kê nhận dạng lưu lượng proxy qua kích thước bản ghi đồng nhất.

### Biến đổi phản hồi ServerHello

Kích thước payload mã hóa của ServerHello thay đổi đến ±32 byte giữa các kết nối, mô phỏng sự biến đổi tự nhiên về kích thước chuỗi chứng chỉ và session ticket từ TLS server thực. ServerHello và ChangeCipherSpec được gửi dưới dạng các đoạn TCP riêng biệt để ngăn DPI so khớp toàn bộ phản hồi bắt tay trong một gói tin.

### Buộc phân mảnh ClientHello (tự động)

Teleproxy thông báo TCP MSS nhỏ (256 byte) trong SYN-ACK trên cổng nghe công khai của proxy. Kernel của client tuân theo giới hạn và chia ClientHello gửi đi (~500-700 byte) thành 2-3 đoạn TCP. Danh sách cipher, phần mở rộng, thuật toán chữ ký và ALPN đều nằm trên ranh giới đoạn — DPI tính JA4 từ một gói tin chỉ thấy một mảnh của dữ liệu cần thiết.

Hoạt động tự động, không cần cấu hình, áp dụng với client Telegram không sửa đổi trên mọi nền tảng. Listener HTTP `/stats` / `/metrics` dùng MSS hệ thống mặc định và không bị ảnh hưởng.

Đánh đổi: Linux áp dụng MSS của socket nghe cho cả hai hướng của mỗi kết nối được chấp nhận, nên các đoạn server→client cũng bị giới hạn ở 256 byte. Số gói tin tăng khoảng 5 lần và phần overhead TCP/IP header tăng từ ~3% lên ~15%. Trên phần cứng hiện đại có TSO/GSO, chi phí CPU vẫn quản lý được, nhưng các proxy bão hòa băng thông sẽ thấy giới hạn thông lượng đáng kể. Mặc định bật phân mảnh — với hầu hết người dùng, một proxy hoạt động nhưng chậm hơn vẫn tốt hơn một proxy nhanh bị chặn.

### Ngẫu nhiên hóa GREASE

Mỗi ClientHello (để thăm dò domain upstream) sử dụng giá trị GREASE mới theo RFC 8701, ngăn chặn so khớp dấu vân tay tĩnh.

## Bạn có thể làm gì (thiết lập server)

### Sử dụng cổng 443

Lưu lượng TLS trên cổng không chuẩn (8443, 6443) gây nghi ngờ. Luôn chạy Teleproxy trên cổng 443:

```bash
./teleproxy -H 443 -S <secret> -D example.com ...
```

### Chọn domain có lưu lượng cao

Chọn domain phổ biến, có CDN cho SNI (ví dụ: `www.google.com`, `cloudflare.com`). Domain phải hỗ trợ TLS 1.3. Teleproxy thăm dò domain khi khởi động để tìm hiểu đặc điểm ServerHello và mô phỏng chúng.

### Chạy TLS backend tùy chỉnh

Nếu bạn quản lý domain của server, hãy thiết lập nginx với chứng chỉ TLS hợp lệ phía sau Teleproxy. Điều này làm cho server không thể phân biệt với website HTTPS bình thường khi bị thăm dò chủ động. Xem [Fake-TLS: TLS Backend Tùy chỉnh](fake-tls.md#custom-tls-backend-tcp-splitting).

### Sử dụng padding ngẫu nhiên (chế độ DD)

Đối với ISP nhận dạng MTProto qua kích thước gói tin, bật padding ngẫu nhiên bằng cách thêm tiền tố `dd` vào secret client.

## Người dùng có thể làm gì (phía client)

Phương thức phát hiện chính là dấu vân tay TLS của client Telegram, điều này **không thể sửa được từ phía server**. Người dùng trong các mạng bị ảnh hưởng nên sử dụng công cụ vượt DPI phía client để phân mảnh đoạn TCP:

| Công cụ | Nền tảng | Phương pháp |
|---------|----------|-------------|
| [zapret](https://github.com/bol-van/zapret) | Linux, Android (root) | Phân mảnh TCP, gói tin giả |
| [zapret2](https://github.com/bol-van/zapret2) | Linux, Android (root) | Fork cập nhật |
| [GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI) | Windows | Phân mảnh TCP, thủ thuật TTL |
| [NoDPI](https://github.com/nicknsy/NoDPI) | Android (không root) | VPN cục bộ với phân mảnh |
| [SpoofDPI](https://github.com/xvzc/SpoofDPI) | macOS, Linux | Proxy chia tách HTTP/TLS |

Các công cụ này hoạt động vì DPI Nga so khớp mẫu trên **đoạn TCP nguyên vẹn**. Phân mảnh ClientHello qua nhiều đoạn sẽ đánh bại bộ so khớp mẫu.

!!! tip "Cập nhật Telegram"
    Telegram Desktop [đã sửa một số artifact dấu vân tay TLS](https://github.com/telegramdesktop/tdesktop/pull/30513) mà DPI khai thác. Client di động (Android/iOS) thường nhận các bản sửa này trong các bản cập nhật tiếp theo. Luôn sử dụng phiên bản mới nhất.

## Những gì không thể sửa từ phía server

- **Dấu vân tay TLS client**: ứng dụng Telegram kiểm soát nội dung ClientHello. Mã proxy phía server không thể thay đổi những gì client gửi.
- **Chặn IP/L3**: khi DPI chặn dải IP của Telegram ở tầng mạng, chỉ VPN hoặc relay trung gian mới có thể giúp.
- **Triển khai TSPU**: DPI của ISP có phát hiện lưu lượng hay không phụ thuộc vào phiên bản phần cứng/phần mềm TSPU — điều này khác nhau theo nhà mạng và khu vực.
