---
description: "Встроенный HTTP-эндпоинт статистики и метрики Prometheus для Teleproxy. Отслеживание подключений, трафика, посекретной нагрузки и состояния DC."
---

# Мониторинг

## HTTP-эндпоинт статистики

```bash
curl http://localhost:8888/stats
```

Требует флаг `--http-stats`. Доступен только из приватных сетей (loopback, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).

### Расширение сетевого доступа

Для доступа из overlay/VPN-сетей (Tailscale, WireGuard, Netbird) используйте `--stats-allow-net`:

```bash
./teleproxy ... --stats-allow-net 100.64.0.0/10 --stats-allow-net fd00::/8
```

Флаг можно указывать несколько раз для нескольких диапазонов. Поддерживается CIDR-нотация IPv4 и IPv6.

## Метрики Prometheus

```bash
curl http://localhost:8888/metrics
```

Возвращает метрики в формате Prometheus exposition на том же порту статистики. Включает посекретные метрики при настроенных метках.

Доступные метрики: количество подключений, подключения по секретам, счётчики отклонений и отклонения по IP ACL.

### Распределение JA4 отпечатков ClientHello

Каждый корректный TLS ClientHello, доходящий до прокси, фингерпринтится по [JA4](https://github.com/FoxIO-LLC/ja4) и попадает в топ-32 счётчик — включая ClientHello, которые потом не проходят HMAC-проверку. Это и есть смысл: когда ТСПУ выкатывает новую сигнатуру блокировки, операционно интересен именно тот зонд, который HMAC *не* проходит. Включено всегда, без настройки.

```
# HELP teleproxy_ja4_seen ClientHello JA4 fingerprints observed (top 32 by count, aggregated across workers).
# TYPE teleproxy_ja4_seen counter
teleproxy_ja4_seen{hash="t13d1615h2_46e7e9700bed_45f260be83e2"} 8
```

В `/stats` те же данные приходят как tab-разделённые строки `ja4_seen\t<hash>\t<count>`. Сверьте распределение со счётчиком пользователей или логами апстрима — фингерпринт, который появляется только когда растёт rate блокировок, и есть новая сигнатура.

Опционально: `--ja4-log` (или `[stats] ja4_log = true` в TOML, `JA4_LOG=true` в Docker) печатает строку `ja4=... sni=...` на каждое подключение при verbose 2. Полезно для разовых разборов, шумно в обычном режиме.

### Зонды задержки DC

При включении teleproxy периодически выполняет TCP-рукопожатие со всеми 5 дата-центрами Telegram и публикует результаты в виде гистограммы Prometheus:

```bash
# Включение с интервалом 30 секунд
./teleproxy ... --dc-probe-interval 30
```

Публикуемые метрики:

| Метрика | Тип | Описание |
|---------|-----|----------|
| `teleproxy_dc_latency_seconds` | histogram | RTT TCP-рукопожатия по DC (метки: `dc="1"`..`dc="5"`) |
| `teleproxy_dc_probe_failures_total` | counter | Неудачные попытки зондирования по DC |
| `teleproxy_dc_latency_last_seconds` | gauge | Последняя измеренная задержка по DC |

Текстовый эндпоинт `/stats` содержит соответствующие поля: `dc_probe_interval`, `dcN_probe_latency_last`, `dcN_probe_latency_avg`, `dcN_probe_count`, `dcN_probe_failures`.

По умолчанию отключено. Задайте `dc_probe_interval` в TOML-конфиге или используйте переменную окружения `DC_PROBE_INTERVAL` в Docker.

## Дашборд Grafana {#grafana-dashboard}

Импортируйте [готовый дашборд](https://github.com/teleproxy/teleproxy/blob/main/dashboards/teleproxy.json) в Grafana:

1. Скачайте `dashboards/teleproxy.json` из репозитория
2. В Grafana: Dashboards → Import → Upload JSON file
3. Выберите источник данных Prometheus

Дашборд охватывает подключения, посекретную нагрузку, частоту отклонений, связность с DC и утилизацию ресурсов.

## Проверка здоровья

Docker-контейнеры включают встроенный мониторинг здоровья через эндпоинт статистики. Проверка:

```bash
docker ps  # столбец STATUS показывает состояние здоровья
```
