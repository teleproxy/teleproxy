# Teleproxy

**[English](README.md)** | **[فارسی](README.fa.md)** | **[Tiếng Việt](README.vi.md)**

Высокопроизводительный MT-Proto прокси для Telegram с защитой от DPI, маскировкой под TLS и мониторингом.

**Возможности**: Fake-TLS (EE-режим), прямое подключение к DC, Dynamic Record Sizing, контроль доступа по IP, Prometheus-метрики, мультисекрет с метками, статические бинарники, Docker, ARM64.

## Установка

### Быстрая установка (RPM)

Для CentOS/RHEL/AlmaLinux с предсобранными пакетами, автообновлениями и настройкой systemd:

### Статический бинарник (любой Linux)

```bash
# Скачать (amd64 или arm64)
curl -Lo teleproxy https://github.com/teleproxy/teleproxy/releases/latest/download/teleproxy-linux-amd64
chmod +x teleproxy

# Сгенерировать секрет
SECRET=$(head -c 16 /dev/urandom | xxd -ps)

# Запустить в direct-режиме (проще всего — не нужны конфиг-файлы)
./teleproxy -S "$SECRET" -H 443 --direct -p 8888 --aes-pwd /dev/null
```

### Docker (быстрый старт)

```bash
docker run -d \
  --name teleproxy \
  -p 443:443 \
  -p 8888:8888 \
  --restart unless-stopped \
  ghcr.io/teleproxy/teleproxy:latest
```

Контейнер автоматически:
- Скачивает конфигурацию от Telegram
- Генерирует случайный секрет (если не задан)
- Запускает прокси на порту 443

Ссылки для подключения — в логах:

```bash
docker logs teleproxy
```

### Docker с Fake-TLS (EE-режим)

```bash
docker run -d \
  --name teleproxy \
  -p 443:443 \
  -p 8888:8888 \
  -e EE_DOMAIN=www.google.com \
  --restart unless-stopped \
  ghcr.io/teleproxy/teleproxy:latest
```

### Docker в direct-режиме

```bash
docker run -d \
  --name teleproxy \
  -p 443:443 \
  -p 8888:8888 \
  -e DIRECT_MODE=true \
  --restart unless-stopped \
  ghcr.io/teleproxy/teleproxy:latest
```

Direct-режим подключается напрямую к серверам Telegram, минуя ME-релеи. Не требует `proxy-multi.conf`. Несовместим с рекламным тегом (`PROXY_TAG`).

## Транспортные режимы

### DD-режим (случайный padding)

Добавляет случайные данные к пакетам для защиты от анализа размеров.

**Секрет клиента:** добавьте префикс `dd` к секрету.

### EE-режим (Fake-TLS)

Трафик выглядит как стандартное TLS 1.3-соединение.

**Секрет клиента:** `ee` + секрет_сервера + hex_домена

```bash
SECRET="cafe1234567890abcdef1234567890ab"
DOMAIN="www.google.com"
echo -n "ee${SECRET}" && echo -n $DOMAIN | xxd -plain
```

### EE-режим с собственным TLS-бэкендом

Запустите nginx с настоящим сертификатом за Teleproxy. Невалидные подключения перенаправляются на nginx — сервер неотличим от обычного веб-сайта.

**DRS (Dynamic Record Sizing):** TLS-записи автоматически варьируются по размеру, имитируя поведение реальных HTTPS-серверов. Никакой настройки не требуется.

## Переменные окружения Docker

| Переменная | По умолчанию | Описание |
|------------|:---:|-----------|
| `SECRET` | авто | Секрет(ы) прокси — 32 hex-символа, через запятую |
| `PORT` | 443 | Порт для клиентских подключений |
| `STATS_PORT` | 8888 | Порт статистики |
| `WORKERS` | 1 | Количество воркеров |
| `PROXY_TAG` | — | Тег от @MTProxybot |
| `DIRECT_MODE` | false | Прямое подключение к DC Telegram |
| `EE_DOMAIN` | — | Домен для Fake-TLS |
| `EXTERNAL_IP` | авто | Публичный IP для NAT |
| `IP_BLOCKLIST` | — | Путь к файлу с CIDR для блокировки |
| `IP_ALLOWLIST` | — | Путь к файлу с CIDR для разрешения |

## Мониторинг

```bash
# Текстовая статистика
curl http://localhost:8888/stats

# Prometheus-метрики
curl http://localhost:8888/metrics
```

Статистика доступна только из приватных сетей (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).

---

Полная документация (сборка из исходников, IPv6, systemd, метки секретов, лимиты подключений): **[README.md](README.md)** (English)
