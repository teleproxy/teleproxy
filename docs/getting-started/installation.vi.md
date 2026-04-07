---
description: "Cài đặt Teleproxy bằng script một dòng, tải binary trực tiếp, hoặc build từ source. Hỗ trợ x86_64 và ARM64 trên Linux."
---

# Cài đặt

## Cài đặt bằng một lệnh (Khuyên dùng) {#one-liner-install-recommended}

Script cài đặt sẽ tải binary, tạo systemd service, sinh secret và in liên kết kết nối:

```bash
curl -sSL https://raw.githubusercontent.com/teleproxy/teleproxy/main/install.sh | sh
```

Tùy chỉnh bằng biến môi trường:

```bash
curl -sSL https://raw.githubusercontent.com/teleproxy/teleproxy/main/install.sh | PORT=8443 EE_DOMAIN=www.google.com sh
```

### Nhiều Secret

Tự động tạo nhiều secret cùng lúc:

```bash
curl -sSL https://raw.githubusercontent.com/teleproxy/teleproxy/main/install.sh | SECRET_COUNT=3 sh
```

Hoặc truyền secret của bạn dưới dạng danh sách phân cách bởi dấu phẩy:

```bash
curl -sSL https://raw.githubusercontent.com/teleproxy/teleproxy/main/install.sh | \
  SECRET=aabbccdd11223344aabbccdd11223344,eeff00112233445566778899aabbccdd sh
```

Secret đánh số với nhãn và giới hạn kết nối riêng cho từng secret:

```bash
curl -sSL https://raw.githubusercontent.com/teleproxy/teleproxy/main/install.sh | \
  SECRET_1=aabbccdd11223344aabbccdd11223344 SECRET_LABEL_1=family \
  SECRET_2=eeff00112233445566778899aabbccdd SECRET_LABEL_2=work SECRET_LIMIT_2=500 \
  sh
```

Mỗi secret sẽ có mã QR và liên kết kết nối riêng khi cài đặt xong. Bạn cũng có thể thêm hoặc xóa secret sau đó bằng cách sửa cấu hình và reload:

```bash
nano /etc/teleproxy/config.toml
systemctl reload teleproxy
```

Sau khi cài đặt, quản lý bằng các lệnh:

```bash
systemctl status teleproxy       # kiểm tra trạng thái
systemctl reload teleproxy       # reload cấu hình sau khi chỉnh sửa
nano /etc/teleproxy/config.toml  # chỉnh sửa cấu hình (secret, port, v.v.)
```

Gỡ cài đặt:

```bash
curl -sSL https://raw.githubusercontent.com/teleproxy/teleproxy/main/install.sh | sh -s -- --uninstall
```

## Cập nhật

Chạy lại script cài đặt để nâng cấp lên phiên bản mới nhất:

```bash
curl -sSL https://raw.githubusercontent.com/teleproxy/teleproxy/main/install.sh | sh
```

Script sẽ thay thế binary và khởi động lại dịch vụ. Cấu hình hiện tại (`/etc/teleproxy/config.toml`) - bao gồm secret, port và thiết lập domain - được giữ nguyên.

Để cài đặt một phiên bản cụ thể:

```bash
curl -sSL https://raw.githubusercontent.com/teleproxy/teleproxy/main/install.sh | TELEPROXY_VERSION=1.2.3 sh
```

## Kho RPM (RHEL, Rocky, Alma, Fedora)

Trên RHEL 9, RHEL 10, AlmaLinux, Rocky Linux và Fedora 41/42, hãy cài qua dnf để bản cập nhật đi qua trình quản lý gói:

```bash
dnf install https://teleproxy.github.io/repo/teleproxy-release-latest.noarch.rpm
dnf install teleproxy
systemctl enable --now teleproxy
```

Lần cài đầu sẽ sinh một secret ngẫu nhiên trong `/etc/teleproxy/config.toml` và thông điệp sau cài đặt sẽ in ra liên kết kết nối. Các lần `dnf upgrade` sau chỉ thay binary và không bao giờ động vào file cấu hình của bạn.

Kho được ký bằng GPG RSA 4096 với SHA-512 (tương thích với rpm-sequoia trên RHEL 9). Gói setup đặt `/etc/yum.repos.d/teleproxy.repo` và khoá công khai vào `/etc/pki/rpm-gpg/`.

Gỡ cài đặt:

```bash
dnf remove teleproxy
```

File `/etc/teleproxy/config.toml` được giữ lại để lần cài lại tiếp tục từ chỗ bạn đã dừng.

## Binary tĩnh (Mọi bản phân phối Linux)

Các binary tĩnh được phát hành cùng với mỗi phiên bản - liên kết tĩnh với musl libc, không cần bất kỳ thư viện phụ thuộc nào. Tải về và chạy ngay.

=== "amd64"

    ```bash
    curl -Lo teleproxy https://github.com/teleproxy/teleproxy/releases/latest/download/teleproxy-linux-amd64
    chmod +x teleproxy
    ```

=== "arm64"

    ```bash
    curl -Lo teleproxy https://github.com/teleproxy/teleproxy/releases/latest/download/teleproxy-linux-arm64
    chmod +x teleproxy
    ```

Mã kiểm tra SHA256 được công bố cùng mỗi phiên bản để xác minh tính toàn vẹn.

## Docker

Xem [Docker Quick Start](../docker/index.md) để biết cách đơn giản nhất để chạy Teleproxy - chỉ một lệnh `docker run` với secret tự động tạo.

## Build từ source

Cài đặt các gói phụ thuộc:

=== "Debian / Ubuntu"

    ```bash
    apt install git curl build-essential libssl-dev zlib1g-dev
    ```

=== "CentOS / RHEL"

    ```bash
    yum groupinstall "Development Tools"
    yum install openssl-devel zlib-devel
    ```

=== "macOS (phát triển)"

    ```bash
    brew install epoll-shim openssl
    ```

    Bản build macOS sử dụng [epoll-shim](https://github.com/jiixyj/epoll-shim) để bọc kqueue sau Linux epoll API, và Homebrew OpenSSL (keg-only). Đây chỉ dành cho phát triển nội bộ - triển khai sản xuất nên dùng Linux.

Clone và build:

```bash
git clone https://github.com/teleproxy/teleproxy
cd teleproxy
make
```

Binary đã biên dịch sẽ nằm tại `objs/bin/teleproxy`.

!!! note
    Nếu build thất bại, chạy `make clean` trước khi thử lại.
