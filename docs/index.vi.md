---
hide:
  - navigation
  - toc
---

<div class="tx-hero" markdown>

# Mở khoá Telegram. Vô hình.

Proxy MTProto hiệu suất cao giúp lưu lượng Telegram không thể phân biệt với HTTPS thông thường — vượt qua kiểm tra gói tin sâu (DPI).

[Bắt đầu](getting-started/quickstart.md){ .md-button .md-button--primary }
[Khởi chạy với Docker](docker/index.md){ .md-button }

:material-send: Theo dõi **[@teleproxy_dev](https://t.me/teleproxy_dev)** trên Telegram để nhận cập nhật.

</div>

<div class="feature-grid" markdown>

<div class="feature" markdown>

### :material-shield-lock-outline: Fake-TLS & Chống DPI

Bọc MTProto trong TLS handshake thật — về mặt thống kê không thể phân biệt với HTTPS bình thường.

</div>

<div class="feature" markdown>

### :material-lightning-bolt: Kết nối trực tiếp đến DC

Bỏ qua các máy chủ trung gian của Telegram, kết nối trực tiếp đến trung tâm dữ liệu gần nhất.

</div>

<div class="feature" markdown>

### :material-chart-line: Giám sát Production

Prometheus metrics endpoint và trang thống kê HTTP để giám sát thời gian thực.

</div>

<div class="feature" markdown>

### :material-docker: Docker Image chỉ 8 MB

Nhỏ hơn 7 lần so với image gốc của Telegram. Hỗ trợ AMD64 và ARM64.

</div>

<div class="feature" markdown>

### :material-key-variant: Nhiều Secret & Kiểm soát truy cập

Tối đa 16 secret với nhãn, giới hạn kết nối và danh sách IP.

</div>

<div class="feature" markdown>

### :material-test-tube: Đã được kiểm chứng

Proxy MTProto duy nhất có E2E test tự động với Telegram thật.

</div>

</div>

## Khởi động nhanh

Chạy proxy bằng một lệnh:

```bash
docker run -d --name teleproxy \
  -p 443:443 \
  --restart unless-stopped \
  ghcr.io/teleproxy/teleproxy:latest
```

Container tạo secret ngẫu nhiên khi khởi động lần đầu và in liên kết `tg://` vào log.

<div class="callout" markdown>

:material-information-outline: **Tài liệu đầy đủ bằng tiếng Anh.** Để xem hướng dẫn cài đặt, cấu hình và tính năng chi tiết, vui lòng xem [phiên bản tiếng Anh](index.md){ hreflang="en" }.

</div>
