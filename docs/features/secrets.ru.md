---
description: "Настройка до 16 прокси-секретов с метками, посекретными лимитами подключений и квотами трафика для гибкого управления доступом."
---

# Секреты и лимиты

## Генерация секретов

Генерация случайного 16-байтного секрета:

```bash
teleproxy generate-secret
```

Для режима fake-TLS укажите домен, чтобы получить полный секрет с префиксом `ee`, готовый для клиентских ссылок:

```bash
teleproxy generate-secret www.google.com
# stdout:  ee<secret><domain-hex>  (для ссылок tg://proxy)
# stderr:  Secret for -S: <secret>  (для флага -S)
```

## Несколько секретов

До 16 секретов, каждый с необязательной меткой:

```bash
./teleproxy ... -S cafe...ab:family -S dead...ef:friends
```

## Метки секретов

Метки идентифицируют, какой секрет использует подключение.

CLI:

```bash
./teleproxy ... -S cafe...ab:family -S dead...ef:friends
```

Установщик:

```bash
curl -sSL .../install.sh | \
  SECRET_1=cafe...ab SECRET_LABEL_1=family \
  SECRET_2=dead...ef SECRET_LABEL_2=friends \
  sh
```

Docker:

```bash
# Метки в одной строке
SECRET=cafe...ab:family,dead...ef:friends

# Или пронумерованные
SECRET_1=cafe...ab
SECRET_LABEL_1=family
SECRET_2=dead...ef
SECRET_LABEL_2=friends
```

Метки отображаются в:

- **Логах:** `TLS handshake matched secret [family] from 1.2.3.4:12345`
- **Prometheus:** `teleproxy_secret_connections{secret="family"} 3`
- **Статистике:** `secret_family_connections	3`

Секреты без метки получают автоматические метки `secret_0`, `secret_1` и т.д.

Правила меток: максимум 32 символа, буквы, цифры, `_` и `-`.

## Посекретные лимиты подключений

Защита от утечки секрета, который может занять все ресурсы:

```bash
# CLI: укажите :LIMIT после метки
./teleproxy ... -S cafe...ab:family:1000 -S dead...ef:public:200

# Без метки
./teleproxy ... -S cafe...ab::500
```

Установщик:

```bash
curl -sSL .../install.sh | \
  SECRET_1=cafe...ab SECRET_LABEL_1=family SECRET_LIMIT_1=1000 \
  SECRET_2=dead...ef SECRET_LABEL_2=public SECRET_LIMIT_2=200 \
  sh
```

Docker:

```bash
# Переменные окружения
SECRET_LIMIT_1=1000
SECRET_LIMIT_2=200

# В одной строке
SECRET=cafe...ab:family:1000,dead...ef:public:200
```

При достижении лимита:

- **Fake-TLS (EE):** отклонение при TLS-рукопожатии — клиент видит бэкенд-сайт
- **Obfuscated2 (DD):** подключение молча сбрасывается

Многопроцессный режим: при `-M N` воркерах каждый применяет `limit / N` независимо.

Метрики:

- **Статистика:** `secret_family_limit 1000`, `secret_family_rejected 42`
- **Prometheus:** `teleproxy_secret_connection_limit{secret="family"} 1000`, `teleproxy_secret_connections_rejected_total{secret="family"} 42`

## Посекретные квоты

Ограничение суммарного объёма переданных данных (принятых + отправленных) по секрету. При исчерпании квоты активные подключения закрываются, новые отклоняются.

TOML-конфиг:

```toml
[[secret]]
key = "cafe...ab"
label = "guest"
quota = "10G"    # допустимо: байты (число), или "500M", "10G", "1T"
```

Docker:

```bash
SECRET_QUOTA_1=10737418240   # 10 ГБ в байтах
```

Квота накапливается с момента запуска — не сбрасывается при перезагрузке конфига по SIGHUP. Для сброса перезапустите прокси.

Метрики:

- **Статистика:** `secret_guest_quota 10737418240`, `secret_guest_bytes_total 5368709120`, `secret_guest_rejected_quota 3`
- **Prometheus:** `teleproxy_secret_quota_bytes{secret="guest"} 10737418240`, `teleproxy_secret_bytes_total{secret="guest"} 5368709120`

## Ограничение скорости по IP

Ограничение пропускной способности в реальном времени для каждого IP-адреса источника. Используется алгоритм token bucket — каждый IP получает корзину, которая пополняется с заданной скоростью. Когда корзина пуста, чтение приостанавливается до пополнения токенов. В отличие от квоты (которая закрывает подключения), ограничение скорости использует TCP backpressure — пользователи видят замедление, а не разрыв соединения.

TOML-конфиг:

```toml
[[secret]]
key = "cafe...ab"
label = "shared"
rate_limit = "10M"   # 10 МБ/с на IP (допустимо: байт/с число, или "500K", "10M")
```

Docker:

```bash
SECRET_RATE_LIMIT_1=10485760   # 10 МБ/с в байтах/с
# или в читаемом формате:
SECRET_RATE_LIMIT_1=10M
```

Ограничение скорости суммарное (принято + отправлено) для каждого IP источника. Размер пакета (burst) равен 1 секунде токенов — новое подключение может отправить данные на полной скорости до начала троттлинга.

Многопроцессный режим: при `-M N` воркерах каждый применяет `rate_limit / N` независимо.

Перезагружаемый: изменение `rate_limit` по SIGHUP вступает в силу немедленно для новых данных.

Метрики:

- **Статистика:** `secret_shared_rate_limit 10485760`, `secret_shared_rate_limited 42`
- **Prometheus:** `teleproxy_secret_rate_limit_bytes{secret="shared"} 10485760`, `teleproxy_secret_rate_limited_total{secret="shared"} 42`

## Посекретный лимит уникальных IP

Ограничение числа уникальных клиентских IP, одновременно использующих секрет. Дополнительные подключения с уже подключённого IP разрешены.

TOML-конфиг:

```toml
[[secret]]
key = "cafe...ab"
label = "guest"
max_ips = 5
```

Docker:

```bash
SECRET_MAX_IPS_1=5
```

Метрики:

- **Статистика:** `secret_guest_max_ips 5`, `secret_guest_unique_ips 3`, `secret_guest_rejected_ips 0`
- **Prometheus:** `teleproxy_secret_max_ips{secret="guest"} 5`, `teleproxy_secret_unique_ips{secret="guest"} 3`

## Срок действия секрета

Автоматическое отключение секрета после заданной метки времени. Новые подключения отклоняются; существующие продолжают работать до естественного закрытия.

TOML-конфиг:

```toml
[[secret]]
key = "cafe...ab"
label = "temp"
expires = 2025-06-30T23:59:59Z    # TOML datetime (UTC)
# или: expires = 1751327999         # Unix timestamp
```

Docker:

```bash
SECRET_EXPIRES_1=2025-06-30T23:59:59Z
# или: SECRET_EXPIRES_1=1751327999
```

Метрики:

- **Статистика:** `secret_temp_expires 1751327999`, `secret_temp_rejected_expired 12`
- **Prometheus:** `teleproxy_secret_expires_timestamp{secret="temp"} 1751327999`

## Пример TOML-конфига

Все посекретные функции в одном конфиге:

```toml
[[secret]]
key = "cafe01234567890abcafe01234567890"
label = "family"
limit = 100
quota = "50G"
rate_limit = "10M"
max_ips = 10
expires = 2026-12-31T23:59:59Z

[[secret]]
key = "dead01234567890abcead01234567890"
label = "guest"
limit = 50
quota = "5G"
rate_limit = "2M"
max_ips = 3
expires = 2025-06-30T00:00:00Z
```
