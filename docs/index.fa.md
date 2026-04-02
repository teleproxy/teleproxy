---
hide:
  - navigation
  - toc
---

<div class="tx-hero" markdown>

<div dir="rtl" markdown>

# تلگرام را آزاد کنید. نامرئی.

پراکسی MTProto با کارایی بالا که ترافیک تلگرام را از HTTPS عادی غیرقابل تشخیص می‌کند — فیلترینگ عمیق بسته‌ها (DPI) را دور می‌زند.

</div>

[شروع کنید](getting-started/quickstart.md){ .md-button .md-button--primary }
[راه‌اندازی با Docker](docker/index.md){ .md-button }

:material-send: **[@teleproxy_dev](https://t.me/teleproxy_dev)** را در تلگرام دنبال کنید.

</div>

<div dir="rtl" markdown>

## ویژگی‌ها

<div class="feature-grid" markdown>

<div class="feature" markdown>

### :material-shield-lock-outline: Fake-TLS و مقاومت در برابر DPI

ترافیک MTProto را در یک handshake واقعی TLS پنهان می‌کند — از نظر آماری غیرقابل تشخیص از HTTPS معمولی.

</div>

<div class="feature" markdown>

### :material-lightning-bolt: اتصال مستقیم به DC

سرورهای واسط تلگرام را دور می‌زند و کلاینت‌ها را مستقیماً به نزدیک‌ترین دیتاسنتر متصل می‌کند.

</div>

<div class="feature" markdown>

### :material-chart-line: مانیتورینگ Production

اندپوینت متریک‌های Prometheus و صفحه آمار HTTP برای نظارت لحظه‌ای.

</div>

<div class="feature" markdown>

### :material-docker: ایمیج Docker فقط ۸ مگابایت

۷ برابر کوچک‌تر از ایمیج اصلی تلگرام. پشتیبانی از AMD64 و ARM64.

</div>

<div class="feature" markdown>

### :material-key-variant: چند Secret و کنترل دسترسی

تا ۱۶ secret با برچسب، محدودیت اتصال و لیست IP.

</div>

<div class="feature" markdown>

### :material-test-tube: تست‌شده در عمل

تنها پراکسی MTProto با تست‌های E2E خودکار علیه تلگرام واقعی.

</div>

</div>

## شروع سریع

با یک دستور پراکسی را اجرا کنید:

</div>

```bash
docker run -d --name teleproxy \
  -p 443:443 \
  --restart unless-stopped \
  ghcr.io/teleproxy/teleproxy:latest
```

<div dir="rtl" markdown>

کانتینر در اولین اجرا یک secret تصادفی تولید می‌کند و لینک اتصال `tg://` را در لاگ‌ها نمایش می‌دهد.

<div class="callout" markdown>

:material-information-outline: **مستندات کامل به زبان انگلیسی موجود است.** برای راهنمای جامع نصب، پیکربندی و ویژگی‌ها، [نسخه انگلیسی](index.md){ hreflang="en" } را ببینید.

</div>

</div>
