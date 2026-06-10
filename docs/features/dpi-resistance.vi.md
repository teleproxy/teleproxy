---
description: "Cách Teleproxy đánh bại kiểm tra gói tin sâu. Phương pháp phát hiện TSPU/ASBI và các biện pháp đối phó phía máy chủ."
---

# Kháng DPI

Teleproxy bao gồm nhiều lớp phòng thủ chống lại hệ thống Kiểm tra Gói tin Sâu (DPI) nhằm phát hiện và chặn lưu lượng MTProxy.

## Bối cảnh mối đe dọa hiện tại

Các hệ thống DPI của Nga (TSPU/ASBI) phân loại MTProxy fake-TLS là một giao thức riêng biệt ("TELEGRAM_TLS"). Việc phát hiện dựa vào **dấu vân tay TLS phía client**: ClientHello của ứng dụng Telegram mang một dấu vân tay JA4 cố định mà DPI so khớp với một chữ ký. Proxy không thể thay đổi điều này — các byte do client Telegram tạo ra, không phải server.

Có hai đợt chặn riêng biệt trong năm 2026:

**Tháng 4 năm 2026 (dấu vân tay tĩnh).** TSPU so khớp JA4/JA3 tĩnh của ClientHello fake-TLS, dựa vào những dấu hiệu mà không trình duyệt thật nào gửi (một mã phần mở rộng lỗi `0xfe02` và một trường ngẫu nhiên 20 byte). Telegram đã sửa các artifact này phía client ([tdesktop PR #30513](https://github.com/telegramdesktop/tdesktop/pull/30513), [DrKLO Android PR #1949](https://github.com/DrKLO/Telegram/pull/1949)), khôi phục kết nối đến cuối tháng 5.

**Cuối tháng 5 – tháng 6 năm 2026 (tái tổ hợp + tương quan luồng).** Bản sửa tháng 4 chỉ đổi một dấu vân tay tĩnh này lấy một dấu vân tay tĩnh khác — client vẫn phát ra một JA4 cố định duy nhất. Đợt này khó hơn:

- **TSPU giờ tái tổ hợp luồng TCP** trước khi lấy dấu vân tay, nên việc chia ClientHello qua nhiều đoạn không còn che giấu được nó. Các thử nghiệm thực địa hạ MSS server xuống rất thấp (256 rồi 88 byte), đã xác nhận trên đường truyền, **vẫn bị chặn** trên các node tái tổ hợp.
- **Tương quan luồng chủ động.** Nhiều ClientHello mang cùng SNI + JA4 của Telegram đến cùng một `ip:port` khiến kết nối bị ngắt tạm thời. IP proxy còn được đối chiếu với bản ghi A của domain ngụy trang — một SNI ngẫu nhiên không phân giải về IP proxy sẽ **không** vượt qua. Xoay vòng SNI qua các domain ngụy trang thật, hoặc trải ra trên nhiều IP/cổng, sẽ đánh bại tương quan này.
- **Rơi gói im lặng, không RST.** Bắt tay TLS hoàn tất; ngay khi dữ liệu ứng dụng MTProto bắt đầu, các gói bị bỏ mà không reset và client tràn ngập gói gửi lại (triệu chứng "kết nối được, rồi rớt sau ~30 giây").

Các quan sát chính:

- **Di động so với gia đình là không đồng đều, không phải chính sách.** Cùng một proxy thường chạy trên mạng di động của một nhà mạng nhưng hỏng trên mạng cố định/gia đình của chính nhà mạng đó (và ngược lại, và iOS so với Android có thể khác nhau). Đây là **triển khai tái tổ hợp không đồng đều trên các node TSPU** — proxy giống hệt nhau; hộp DPI trên đường truyền khác nhau — không phải quyết định của nhà mạng. Beeline, MTS, Megafon, Rostelecom đều được báo cáo theo cả hai chiều.
- **VPN / đường hầm Reality vượt qua** hoàn toàn dấu vân tay MTProto (xem playbook operator bên dưới).
- **Công cụ phân mảnh phía client** (zapret, GoodbyeDPI) vẫn giúp được trên các đường **không tái tổ hợp**, nhưng giờ phụ thuộc vào đường truyền vì một số node đã tái tổ hợp.
- Việc ngẫu nhiên hóa dấu vân tay client của Telegram (bản sửa bền vững) [vẫn đang được thảo luận ở thượng nguồn](https://github.com/telegramdesktop/tdesktop/issues/30733) và chưa được phát hành.

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

Teleproxy thông báo TCP MSS nhỏ (256 byte) trong SYN-ACK trên cổng nghe công khai của proxy. Kernel của client tuân theo giới hạn và chia ClientHello gửi đi (~500-700 byte) thành 2-3 đoạn TCP, nên các dữ liệu cần cho JA4 (ALPN, `signature_algorithms`) rơi vào các đoạn sau.

**Đánh giá trung thực (cập nhật tháng 6 năm 2026).** Cách này chỉ đánh bại DPI lấy dấu vân tay từ một gói tin. Đợt TSPU hiện tại **tái tổ hợp luồng TCP** trước khi băm, nên trên các node đó việc phân mảnh không có tác dụng gì — các thử nghiệm thực địa hạ MSS xuống tận 88 byte, đã xác nhận trên đường truyền, vẫn bị chặn. Nó vẫn hữu ích với các node không tái tổ hợp (một số đường di động) và kết hợp với việc phân đoạn ServerHello sẵn có, nên mặc định vẫn bật. Nhưng tự nó **không** phải bản sửa cho đợt tháng 6 — xem playbook operator bên dưới để biết điều gì thực sự giúp ích lúc này.

Hoạt động tự động, không cần cấu hình, áp dụng với client Telegram không sửa đổi trên mọi nền tảng. Listener HTTP `/stats` / `/metrics` dùng MSS hệ thống mặc định và không bị ảnh hưởng.

Đánh đổi: Linux áp dụng MSS của socket nghe cho cả hai hướng của mỗi kết nối được chấp nhận, nên các đoạn server→client cũng bị giới hạn ở 256 byte. Số gói tin tăng khoảng 5 lần và phần overhead TCP/IP header tăng từ ~3% lên ~15%. Trên phần cứng hiện đại có TSO/GSO, chi phí CPU vẫn quản lý được, nhưng các proxy bão hòa băng thông sẽ thấy giới hạn thông lượng đáng kể.

**Cách tắt.** Các operator muốn chấp nhận rủi ro bị JA4 phát hiện thay vì chịu overhead thông lượng có thể tắt MSS clamp:

- TOML: `mss_clamp = false` (khoá cấp cao nhất)
- CLI: `--no-mss-clamp`
- Docker / `start.sh`: `MSS_CLAMP=false` (hoặc `MSS_CLAMP=0`)

Bất kỳ cách nào ở trên đều đưa MSS thông báo trong SYN-ACK trở về giá trị hệ thống mặc định — mọi kết nối được chấp nhận sẽ có MSS bình thường ở cả hai hướng, và proxy mang lưu lượng MTProto khối lượng lớn ở tốc độ tối đa. Mặc định vẫn bật phân mảnh — với hầu hết người dùng, một proxy hoạt động hơi chậm hơn vẫn tốt hơn một proxy nhanh nhưng bị chặn.

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

Đối với ISP nhận dạng MTProto qua kích thước gói tin, bật padding ngẫu nhiên bằng cách thêm tiền tố `dd` vào secret client. Lưu ý trung thực: cách này giúp chống lại heuristic dựa trên kích thước gói ở một số ISP, nhưng không có tác dụng gì với việc phát hiện JA4 đang dẫn dắt đợt tháng 6 năm 2026 — đừng chỉ dựa vào nó.

## Vượt qua đợt tháng 6 năm 2026 (playbook operator)

Đợt hiện tại dựa vào JA4 của client cộng với tương quan `(SNI + ip:port)`, và tái tổ hợp TCP. Các thủ thuật dấu vân tay phía server không thể đổi JA4 của client, nên những biện pháp thực sự trụ được trong thực địa là về việc **làm loãng tương quan** và **đưa chặng ra ngoài khỏi MTProto**. Theo thứ tự ưu tiên đại khái:

### 1. Xoay vòng SNI qua nhiều domain ngụy trang thật

Tương quan kích hoạt khi nhiều kết nối cùng SNI + JA4 của Telegram đến cùng một `ip:port`. Đăng ký nhiều domain ngụy trang và phát cho người dùng khác nhau các link với SNI khác nhau:

```bash
./teleproxy -H 443 -S <secret> \
  -D www.cloudflare.com:127.0.0.1:8443 \
  -D www.microsoft.com:127.0.0.1:8443 \
  -D www.apple.com:127.0.0.1:8443
```

Mỗi domain có [SNI tách khỏi backend](fake-tls.md) (`EE_DOMAIN`/`EE_BACKEND`, hoặc dạng `-D sni:backend:port`), nên tất cả có thể dùng chung một TLS backend cục bộ. Chứng chỉ wildcard (`-D '*.example.com:backend:443'`) cũng hoạt động.

**Bản ghi A của domain ngụy trang phải phân giải về IP proxy.** Một SNI ngẫu nhiên trỏ nơi khác sẽ trượt phép đối chiếu bản ghi A của tháng 6. Hãy dùng các domain bạn sở hữu (hoặc host chứng chỉ wildcard) thực sự trỏ về proxy.

### 2. Trải ra trên nhiều IP và cổng, và giữ IP sạch

Nhiều IP/cổng nghe sẽ làm loãng thêm tương quan theo `ip:port`. Lưu ý rằng việc ban IP sau khi phát hiện đã được quan sát thấy lan sang **các IP lân cận trong cùng dải** — hãy trải IP proxy ra nhiều dải thay vì gom cụm, và xoay vòng IP đã bị cháy.

### 3. Cascade chặng ra ngoài qua VLESS + Reality (lựa chọn mạnh nhất)

Cách trụ vững nhất được xác nhận trong thực địa là ngừng gửi lưu lượng dạng-MTProto ra khỏi mạng bị kiểm duyệt: chạy teleproxy ở [chế độ trực tiếp](direct-mode.md) và định tuyến các kết nối **ra ngoài** tới DC qua một client [Xray VLESS + Reality](https://github.com/XTLS/Xray-core) cục bộ trên [SOCKS5](socks5.md):

```bash
# teleproxy trên máy trong nước, lưu lượng tới DC đi ra qua Xray Reality cục bộ
DIRECT_MODE=true
SOCKS5_PROXY=socks5://127.0.0.1:1080   # đầu ra Xray Reality cục bộ
```

Client Telegram vẫn tới teleproxy qua fake-TLS ở cục bộ, nhưng thứ vượt biên giới TSPU là Reality, thứ mà đợt hiện tại không chặn. Lưu ý [các đánh đổi của chế độ trực tiếp](direct-mode.md) (media trên tài khoản không phải Premium, kênh được tài trợ). Cách này cần thiết lập nhiều hơn, nhưng đó là thứ tiếp tục hoạt động khi fake-TLS thông thường không còn.

## Người dùng có thể làm gì (phía client)

Phương thức phát hiện chính là dấu vân tay TLS của client Telegram, điều này **không thể sửa được từ phía server**. Người dùng trong các mạng bị ảnh hưởng nên sử dụng công cụ vượt DPI phía client để phân mảnh đoạn TCP:

| Công cụ | Nền tảng | Phương pháp |
|---------|----------|-------------|
| [zapret](https://github.com/bol-van/zapret) | Linux, Android (root) | Phân mảnh TCP, gói tin giả |
| [zapret2](https://github.com/bol-van/zapret2) | Linux, Android (root) | Fork cập nhật |
| [GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI) | Windows | Phân mảnh TCP, thủ thuật TTL |
| [NoDPI](https://github.com/nicknsy/NoDPI) | Android (không root) | VPN cục bộ với phân mảnh |
| [SpoofDPI](https://github.com/xvzc/SpoofDPI) | macOS, Linux | Proxy chia tách HTTP/TLS |

Các công cụ này phân mảnh ClientHello qua nhiều đoạn TCP. Trên các đường **không tái tổ hợp** điều này vẫn giúp ích, nhưng đợt tháng 6 tái tổ hợp luồng trên một số node, nên kết quả phụ thuộc vào đường truyền — cứ thử, nhưng đây không còn là bản sửa đảm bảo nữa.

!!! tip "Cập nhật Telegram, và theo dõi công việc ngẫu nhiên hóa"
    Bản sửa bền vững là **client tự ngẫu nhiên hóa dấu vân tay TLS** thay vì phát ra một JA4 cố định. Công việc này đang diễn ra ở thượng nguồn nhưng **chưa được phát hành**: [tdesktop #30733](https://github.com/telegramdesktop/tdesktop/issues/30733) theo dõi yêu cầu xoay vòng/ngẫu nhiên hóa JA4, với các PR đang mở ([#30528](https://github.com/telegramdesktop/tdesktop/pull/30528), [#30738](https://github.com/telegramdesktop/tdesktop/pull/30738)) và nỗ lực kỹ lưỡng hơn [telemt/tdlib-obf](https://github.com/telemt/tdlib-obf) (ngụy trang ClientHello theo các profile trình duyệt thật dựa trên pcap). Bản sửa dấu vân tay tháng 4 ([tdesktop #30513](https://github.com/telegramdesktop/tdesktop/pull/30513)) đã có trong các bản phát hành hiện tại — luôn chạy client mới nhất, nhưng hiểu rằng nó vẫn phát một JA4 cố định cho đến khi ngẫu nhiên hóa được đưa vào.

## Những gì không thể sửa từ phía server

- **Dấu vân tay TLS client**: ứng dụng Telegram kiểm soát nội dung từng byte của ClientHello, và TSPU nằm giữa client và proxy. Mã phía server không thể thay đổi những gì client gửi. MSS clamp có thể trải các byte đó qua nhiều đoạn TCP, nhưng các node DPI tái tổ hợp luồng — như đợt tháng 6 năm 2026 — vẫn tính ra đúng JA4. Bản sửa thực sự duy nhất cho dấu vân tay là ở phía client (xem ở trên).
- **Chặn IP/L3 và ban IP**: khi DPI chặn một IP ở tầng mạng — gồm cả các lệnh ban sau phát hiện lan sang IP lân cận trong cùng dải — chỉ VPN, một cascade Reality, hoặc chuyển sang IP sạch mới giúp được.
- **Khác biệt triển khai TSPU**: một đường truyền cụ thể có phát hiện lưu lượng hay không phụ thuộc vào phiên bản phần cứng/phần mềm của node TSPU đó và việc nó có tái tổ hợp TCP hay không. Điều này khác nhau theo nhà mạng, khu vực, và thậm chí giữa mạng di động và cố định của cùng một nhà mạng.
