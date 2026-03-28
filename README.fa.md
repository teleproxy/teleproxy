# Teleproxy

**[English](README.md)** | **[Русский](README.ru.md)** | **[Tiếng Việt](README.vi.md)**

پروکسی MT-Proto با کارایی بالا برای تلگرام با مقاومت در برابر DPI، استتار TLS و نظارت.

**ویژگی‌ها**: Fake-TLS (حالت EE)، اتصال مستقیم به DC، Dynamic Record Sizing، کنترل دسترسی IP، متریک‌های Prometheus، چند سیکرت با برچسب، باینری استاتیک، Docker، ARM64.

| ویژگی | [اصلی](https://github.com/TelegramMessenger/MTProxy) | **این فورک** | [mtg](https://github.com/9seconds/mtg) | [telemt](https://github.com/telemt/telemt) |
|---------|:---:|:---:|:---:|:---:|
| **زبان** | C | C | Go | Rust |
| ***پروتکل*** | | | | |
| Fake-TLS (حالت EE) | بله | بله | بله | بله |
| اتصال مستقیم به DC | خیر | بله | بله | بله |
| تگ تبلیغاتی | بله | بله | خیر | بله |
| چند سیکرت | بله | بله (تا ۱۶، با برچسب) | خیر | بله |
| محافظت ضد replay | ضعیف | بله | بله | جزئی |
| HMAC با زمان ثابت | خیر | بله | — | بله |
| ***مقاومت در برابر DPI*** | | | | |
| بک‌اند TLS سفارشی | بله | بله | خیر | بله |
| تغییر اندازه رکورد پویا (DRS) | خیر | بله | بله | خیر |
| تقلید ترافیک (DRS + زمان‌بندی) | خیر | بله | بله | خیر |
| پروکسی SOCKS5 بالادست | خیر | خیر | بله | بله |
| ***کنترل دسترسی*** | | | | |
| لیست سیاه/سفید IP | خیر | بله | بله | خیر |
| محدودیت IP هر کاربر | خیر | خیر | خیر | بله |
| Proxy Protocol v1/v2 | خیر | خیر | بله | بله |
| ***استقرار*** | | | | |
| اندازه Docker | ~57 MB | ~8 MB | ~3.5 MB | ~5 MB |
| ARM64 / Apple Silicon | خیر | بله | بله | بله |
| IPv6 | بله | بله | بله | بله |
| Multi-worker | بله | بله | — | — |
| باینری استاتیک | خیر | بله | بله | بله |
| ***نظارت*** | | | | |
| متریک‌های Prometheus | خیر | بله | بله | بله |
| آمار HTTP | بله | بله | — | بله |
| Health check | خیر | بله | بله | بله |
| ***تست*** | | | | |
| تست فازینگ (CI) | خیر | بله | خیر | جزئی |
| تست E2E (Telethon) | خیر | بله | خیر | خیر |
| تحلیل استاتیک (CI) | خیر | بله | بله | — |

## نصب

### باینری استاتیک (هر لینوکسی)

```bash
# دانلود (amd64 یا arm64)
curl -Lo teleproxy https://github.com/teleproxy/teleproxy/releases/latest/download/teleproxy-linux-amd64
chmod +x teleproxy

# ایجاد سیکرت
SECRET=$(head -c 16 /dev/urandom | xxd -ps)

# اجرا در حالت direct (ساده‌ترین — بدون نیاز به فایل پیکربندی)
./teleproxy -S "$SECRET" -H 443 --direct -p 8888 --aes-pwd /dev/null
```

### Docker (شروع سریع)

```bash
docker run -d \
  --name teleproxy \
  -p 443:443 \
  -p 8888:8888 \
  --restart unless-stopped \
  ghcr.io/teleproxy/teleproxy:latest
```

کانتینر به طور خودکار:
- پیکربندی را از تلگرام دانلود می‌کند
- سیکرت تصادفی تولید می‌کند (اگر ارائه نشده باشد)
- پروکسی را روی پورت 443 شروع می‌کند

لینک‌های اتصال در لاگ‌ها:

```bash
docker logs teleproxy
```

### Docker با Fake-TLS (حالت EE)

```bash
docker run -d \
  --name teleproxy \
  -p 443:443 \
  -p 8888:8888 \
  -e EE_DOMAIN=www.google.com \
  --restart unless-stopped \
  ghcr.io/teleproxy/teleproxy:latest
```

### Docker در حالت Direct

```bash
docker run -d \
  --name teleproxy \
  -p 443:443 \
  -p 8888:8888 \
  -e DIRECT_MODE=true \
  --restart unless-stopped \
  ghcr.io/teleproxy/teleproxy:latest
```

حالت direct به طور مستقیم به سرورهای تلگرام متصل می‌شود و رله‌های ME را دور می‌زند. به `proxy-multi.conf` نیازی ندارد. با تگ تبلیغاتی (`PROXY_TAG`) سازگار نیست.

## حالت‌های انتقال

### حالت DD (padding تصادفی)

داده‌های تصادفی به بسته‌ها اضافه می‌کند تا از تحلیل اندازه بسته‌ها محافظت کند.

**سیکرت کلاینت:** پیشوند `dd` به سیکرت اضافه کنید.

### حالت EE (Fake-TLS)

ترافیک مانند یک اتصال استاندارد TLS 1.3 به نظر می‌رسد.

**سیکرت کلاینت:** `ee` + سیکرت_سرور + hex_دامنه

```bash
SECRET="cafe1234567890abcdef1234567890ab"
DOMAIN="www.google.com"
echo -n "ee${SECRET}" && echo -n $DOMAIN | xxd -plain
```

### حالت EE با بک‌اند TLS سفارشی

nginx با گواهی واقعی پشت Teleproxy اجرا کنید. اتصالات نامعتبر به nginx هدایت می‌شوند — سرور از یک وب‌سایت معمولی قابل تشخیص نیست.

**DRS (تغییر اندازه رکورد پویا):** رکوردهای TLS به طور خودکار از نظر اندازه متفاوت هستند و رفتار سرورهای واقعی HTTPS را تقلید می‌کنند. نیازی به پیکربندی نیست.

## متغیرهای محیطی Docker

| متغیر | پیش‌فرض | توضیحات |
|------------|:---:|-----------|
| `SECRET` | خودکار | سیکرت(های) پروکسی — ۳۲ کاراکتر hex، جدا با کاما |
| `PORT` | 443 | پورت اتصال کلاینت |
| `STATS_PORT` | 8888 | پورت آمار |
| `WORKERS` | 1 | تعداد worker |
| `PROXY_TAG` | — | تگ از @MTProxybot |
| `DIRECT_MODE` | false | اتصال مستقیم به DC تلگرام |
| `EE_DOMAIN` | — | دامنه برای Fake-TLS |
| `EXTERNAL_IP` | خودکار | IP عمومی برای NAT |

## نظارت

```bash
# آمار متنی
curl http://localhost:8888/stats

# متریک‌های Prometheus
curl http://localhost:8888/metrics
```

---

مستندات کامل (ساخت از سورس، IPv6، systemd، برچسب سیکرت، محدودیت اتصال): **[README.md](README.md)** (English)
