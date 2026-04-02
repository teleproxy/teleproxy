---
hide:
  - navigation
  - toc
---

<div class="tx-hero" markdown>

# Telegram без блокировок. Незаметно.

Высокопроизводительный MTProto-прокси, который делает трафик Telegram неотличимым от обычного HTTPS — обходит DPI и при этом работает быстрее оригинала.

[Начать](getting-started/quickstart.md){ .md-button .md-button--primary }
[Запуск в Docker](docker/index.md){ .md-button }

:material-send: Следите за обновлениями в **[@teleproxy_dev](https://t.me/teleproxy_dev)**.

</div>

<div class="feature-grid" markdown>

<div class="feature" markdown>

### :material-shield-lock-outline: Fake-TLS и обход DPI

MTProto оборачивается в настоящий TLS-хэндшейк с Dynamic Record Sizing — трафик прокси статистически неотличим от обычного просмотра веб-страниц по HTTPS.

</div>

<div class="feature" markdown>

### :material-lightning-bolt: Прямое подключение к DC

Минует промежуточные relay-серверы Telegram, направляя клиентов напрямую к ближайшему дата-центру. Результат — заметно ниже задержки и выше скорость.

</div>

<div class="feature" markdown>

### :material-chart-line: Мониторинг для продакшена

Встроенный эндпоинт Prometheus-метрик и HTTP-страница статистики дают полную видимость: соединения, трафик, нагрузка по каждому секрету — в реальном времени.

</div>

<div class="feature" markdown>

### :material-docker: Docker-образ 8 МБ

Минимальный контейнер на базе scratch — в 7 раз меньше оригинального образа от Telegram. Работает на AMD64 и ARM64, включая Apple Silicon.

</div>

<div class="feature" markdown>

### :material-key-variant: Мульти-секрет и контроль доступа

До 16 секретов с человекочитаемыми метками, лимитами подключений на секрет и IP-списками (белый/чёрный) для гибкого управления доступом.

</div>

<div class="feature" markdown>

### :material-test-tube: Проверено на боевом трафике

Единственный MTProto-прокси с автоматическими E2E-тестами против настоящего Telegram — каждый коммит проверяется реальными подключениями через Telethon по обоим транспортам: obfs2 и fake-TLS.

</div>

</div>

## Быстрый старт

Запуск прокси одной командой:

```bash
docker run -d --name teleproxy \
  -p 443:443 \
  --restart unless-stopped \
  ghcr.io/teleproxy/teleproxy:latest
```

Контейнер генерирует случайный секрет при первом запуске и выводит ссылку `tg://` для подключения в логи.

<div class="callout" markdown>

:material-check-decagram: **Единственный MTProto-прокси с автоматическими E2E-тестами против настоящего Telegram** — каждый коммит проверяется реальными клиентскими подключениями по обоим транспортным режимам. Ни одна другая реализация этого не делает.

</div>

## Что такое Teleproxy?

Teleproxy — это MTProto-прокси, специализированный relay-сервер для Telegram. В отличие от VPN и SOCKS, MTProto-прокси пропускает только трафик Telegram, не требует никакой настройки на стороне клиента (достаточно отсканировать ссылку) и нативно поддерживается во всех официальных приложениях Telegram.

Teleproxy — полноценная замена [заброшенному официальному прокси](https://github.com/TelegramMessenger/MTProxy) от Telegram, переработанная с современным обходом DPI, мониторингом для продакшена и радикально меньшим размером.

## Документация

- **[Быстрый старт](getting-started/quickstart.md)** — Установка и запуск за минуту
- **[Развёртывание в Docker](docker/index.md)** — Образы, Compose-файлы, параметры конфигурации
- **[Fake-TLS и обход DPI](features/fake-tls.md)** — Как работает TLS-камуфляж
- **[Прямое подключение к DC](features/direct-mode.md)** — Почему задержки ниже
- **[Мониторинг](features/monitoring.md)** — Метрики Prometheus и HTTP-статистика
- **[Секреты и контроль доступа](features/secrets.md)** — Настройка нескольких секретов и лимитов
- **[Сравнение](comparison.md)** — Чем Teleproxy отличается от альтернатив
