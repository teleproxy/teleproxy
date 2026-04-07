---
description: "نصب Teleproxy با اسکریپت یک‌خطی، دانلود مستقیم باینری، یا ساخت از سورس. پشتیبانی از x86_64 و ARM64 روی لینوکس."
---

# نصب

## نصب با یک دستور (پیشنهادی) {#one-liner-install-recommended}

اسکریپت نصب باینری را دانلود می‌کند، سرویس systemd را ایجاد می‌کند، یک secret تولید می‌کند و لینک اتصال را نمایش می‌دهد:

```bash
curl -sSL https://raw.githubusercontent.com/teleproxy/teleproxy/main/install.sh | sh
```

سفارشی‌سازی با متغیرهای محیطی:

```bash
curl -sSL https://raw.githubusercontent.com/teleproxy/teleproxy/main/install.sh | PORT=8443 EE_DOMAIN=www.google.com sh
```

### چند secret

تولید خودکار چند secret به‌صورت هم‌زمان:

```bash
curl -sSL https://raw.githubusercontent.com/teleproxy/teleproxy/main/install.sh | SECRET_COUNT=3 sh
```

یا ارسال secret‌های دلخواه به‌صورت لیست جدا شده با کاما:

```bash
curl -sSL https://raw.githubusercontent.com/teleproxy/teleproxy/main/install.sh | \
  SECRET=aabbccdd11223344aabbccdd11223344,eeff00112233445566778899aabbccdd sh
```

secret‌های شماره‌دار با برچسب و محدودیت اتصال مجزا:

```bash
curl -sSL https://raw.githubusercontent.com/teleproxy/teleproxy/main/install.sh | \
  SECRET_1=aabbccdd11223344aabbccdd11223344 SECRET_LABEL_1=family \
  SECRET_2=eeff00112233445566778899aabbccdd SECRET_LABEL_2=work SECRET_LIMIT_2=500 \
  sh
```

برای هر secret یک کد QR و لینک اتصال جداگانه در پایان نصب نمایش داده می‌شود. همچنین می‌توانید بعدا با ویرایش فایل پیکربندی و بارگذاری مجدد، secret اضافه یا حذف کنید:

```bash
nano /etc/teleproxy/config.toml
systemctl reload teleproxy
```

پس از نصب، مدیریت سرویس:

```bash
systemctl status teleproxy       # بررسی وضعیت
systemctl reload teleproxy       # بارگذاری مجدد پیکربندی پس از ویرایش
nano /etc/teleproxy/config.toml  # ویرایش پیکربندی (secret‌ها، پورت‌ها و غیره)
```

حذف نصب:

```bash
curl -sSL https://raw.githubusercontent.com/teleproxy/teleproxy/main/install.sh | sh -s -- --uninstall
```

## به‌روزرسانی

برای ارتقا به آخرین نسخه، اسکریپت نصب را دوباره اجرا کنید:

```bash
curl -sSL https://raw.githubusercontent.com/teleproxy/teleproxy/main/install.sh | sh
```

اسکریپت باینری را جایگزین کرده و سرویس را مجددا راه‌اندازی می‌کند. پیکربندی فعلی (`/etc/teleproxy/config.toml`) شامل secret‌ها، پورت‌ها و تنظیمات دامنه حفظ می‌شود.

برای نصب یک نسخه مشخص:

```bash
curl -sSL https://raw.githubusercontent.com/teleproxy/teleproxy/main/install.sh | TELEPROXY_VERSION=1.2.3 sh
```

## مخزن RPM (RHEL، Rocky، Alma، Fedora)

برای RHEL 9، RHEL 10، AlmaLinux، Rocky Linux و Fedora 41/42 از طریق dnf نصب کنید تا به‌روزرسانی‌ها از طریق پکیج منیجر انجام شوند:

```bash
dnf install https://teleproxy.github.io/repo/teleproxy-release-latest.noarch.rpm
dnf install teleproxy
systemctl enable --now teleproxy
```

نصب اول یک secret تصادفی در `/etc/teleproxy/config.toml` می‌سازد و پیام پس از نصب لینک اتصال را چاپ می‌کند. اجراهای بعدی `dnf upgrade` فقط باینری را عوض می‌کنند و هرگز کانفیگ شما را دست نمی‌زنند.

مخزن با کلید GPG از نوع RSA 4096 و SHA-512 امضا شده (سازگار با rpm-sequoia در RHEL 9). پکیج setup هم `/etc/yum.repos.d/teleproxy.repo` و هم کلید عمومی را در `/etc/pki/rpm-gpg/` قرار می‌دهد.

حذف:

```bash
dnf remove teleproxy
```

فایل `/etc/teleproxy/config.toml` سر جایش می‌ماند تا نصب مجدد از همان‌جایی که رها کردید ادامه پیدا کند.

## باینری استاتیک (هر لینوکسی)

باینری‌های استاتیک از پیش ساخته‌شده با هر انتشار منتشر می‌شوند. این باینری‌ها به‌صورت استاتیک با musl libc لینک شده‌اند و هیچ وابستگی اجرایی ندارند. دانلود کنید و اجرا کنید.

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

چک‌سام‌های SHA256 همراه هر انتشار برای تایید صحت منتشر می‌شوند.

## Docker

برای ساده‌ترین روش اجرای Teleproxy، بخش [شروع سریع Docker](../docker/index.md) را ببینید. تنها یک دستور `docker run` با تولید خودکار secret.

## ساخت از سورس

نصب وابستگی‌های ساخت:

=== "Debian / Ubuntu"

    ```bash
    apt install git curl build-essential libssl-dev zlib1g-dev
    ```

=== "CentOS / RHEL"

    ```bash
    yum groupinstall "Development Tools"
    yum install openssl-devel zlib-devel
    ```

=== "macOS (توسعه)"

    ```bash
    brew install epoll-shim openssl
    ```

    ساخت روی macOS از [epoll-shim](https://github.com/jiixyj/epoll-shim) برای شبیه‌سازی API لینوکس epoll از طریق kqueue و OpenSSL نصب‌شده با Homebrew استفاده می‌کند. این روش برای توسعه محلی در نظر گرفته شده است و برای محیط عملیاتی باید از لینوکس استفاده کنید.

کلون و ساخت:

```bash
git clone https://github.com/teleproxy/teleproxy
cd teleproxy
make
```

باینری کامپایل‌شده در مسیر `objs/bin/teleproxy` قرار خواهد داشت.

!!! note
    اگر ساخت با خطا مواجه شد، قبل از تلاش مجدد دستور `make clean` را اجرا کنید.
