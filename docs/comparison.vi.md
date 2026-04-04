# So sánh

Teleproxy là một fork của [TelegramMessenger/MTProxy](https://github.com/TelegramMessenger/MTProxy) gốc, dự án đã ngừng phát triển từ năm 2021. Trang này so sánh Teleproxy với bản gốc và các phương án thay thế chính từ bên thứ ba: [mtg](https://github.com/9seconds/mtg) (Go) và [telemt](https://github.com/telemt/telemt) (Rust).

| Tính năng | [Gốc](https://github.com/TelegramMessenger/MTProxy) | **[Teleproxy](https://github.com/teleproxy/teleproxy)** | [mtg](https://github.com/9seconds/mtg) | [telemt](https://github.com/telemt/telemt) |
|---------|:---:|:---:|:---:|:---:|
| **Ngôn ngữ** | C | C | Go | Rust |
| ***Giao thức*** | | | | |
| Fake-TLS (chế độ EE) | Có | Có | Có | Có |
| Kết nối trực tiếp DC | Không | Có | Có | Có |
| Tag quảng cáo | Có | Có | Không | Có |
| Nhiều secret | Có | Có (tối đa 16, có nhãn) | Không | Có |
| Chống replay attack | Yếu | Có | Có | Có |
| HMAC thời gian hằng | Không | Có | Có | Có |
| ***Kháng DPI*** | | | | |
| TLS backend tùy chỉnh (TCP splitting) | Có | Có | Có | Có |
| Dynamic Record Sizing (DRS) | Không | Có | Có | Không |
| Giả lập traffic (DRS + timing) | Không | Có | Có | Một phần |
| Phân mảnh ServerHello | Không | Có | Không | Không |
| SOCKS5 upstream proxy | Không | Có | Có | Có |
| DNS over HTTPS/TLS | Không | Không | Có | Không |
| ***Kiểm soát truy cập*** | | | | |
| IP blocklist / allowlist | Không | Có | Có | Không |
| Giới hạn IP theo user | Không | Có | Không | Có |
| Hạn mức lưu lượng theo secret | Không | Có | Không | Có |
| Hết hạn secret | Không | Có | Không | Có |
| Proxy Protocol v1/v2 | Không | Có | Có | Có |
| ***Triển khai*** | | | | |
| Dung lượng Docker | ~57 MB | ~8 MB | ~3,5 MB | ~5 MB |
| ARM64 / Apple Silicon | Không | Có | Có | Có |
| IPv6 | Có | Có | Có | Có |
| Tiến trình multi-worker | Có | Có | — | — |
| Binary tĩnh | Không | Có | Có | Có |
| Gói RPM | Không | Có | Không | Không |
| Tích hợp systemd | Một phần | Có | Không | Có |
| ***Giám sát và quản lý*** | | | | |
| Prometheus metrics | Không | Có | Có | Có |
| HTTP stats endpoint | Có | Có | Không | Có |
| REST management API | Không | Không | Không | Có |
| Tự động cập nhật cấu hình | Không | Có | Có | Có |
| Health check | Không | Có | Có | Có |
| ***Kiểm thử và chất lượng*** | | | | |
| Fuzz testing (CI) | Không | Có | Không | Một phần |
| E2E test (client Telegram thực) | Không | Có | Không | Không |
| Xác thực dấu vân tay TLS (CI) | Không | Có | Không | Không |
| Quét bảo mật CodeQL | Không | Có | Không | Không |
| AddressSanitizer CI | Không | Có | Không | Không |
| Phân tích tĩnh (CI) | Không | Có | Có | — |

Teleproxy là triển khai MTProto proxy duy nhất có kiểm thử đầu-cuối (E2E) tự động trên hạ tầng Telegram thực. Bộ kiểm thử E2E kết nối client Telethon qua proxy trên cả hai transport obfuscated và fake-TLS, xác minh xác thực và truyền file trên datacenter thử nghiệm của Telegram.
