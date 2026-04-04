# Установка

## Установка одной командой (рекомендуется)

Скрипт скачает бинарник, создаст systemd-сервис, сгенерирует секрет и выведет ссылку для подключения:

```bash
curl -sSL https://raw.githubusercontent.com/teleproxy/teleproxy/main/install.sh | sh
```

Настройка через переменные окружения:

```bash
curl -sSL https://raw.githubusercontent.com/teleproxy/teleproxy/main/install.sh | PORT=8443 EE_DOMAIN=www.google.com sh
```

### Несколько секретов

Автоматически сгенерировать несколько секретов:

```bash
curl -sSL https://raw.githubusercontent.com/teleproxy/teleproxy/main/install.sh | SECRET_COUNT=3 sh
```

Или передать свои через запятую:

```bash
curl -sSL https://raw.githubusercontent.com/teleproxy/teleproxy/main/install.sh | \
  SECRET=aabbccdd11223344aabbccdd11223344,eeff00112233445566778899aabbccdd sh
```

Нумерованные секреты с метками и лимитами подключений:

```bash
curl -sSL https://raw.githubusercontent.com/teleproxy/teleproxy/main/install.sh | \
  SECRET_1=aabbccdd11223344aabbccdd11223344 SECRET_LABEL_1=family \
  SECRET_2=eeff00112233445566778899aabbccdd SECRET_LABEL_2=work SECRET_LIMIT_2=500 \
  sh
```

Для каждого секрета будет выведен свой QR-код и ссылка. Добавить или удалить секреты после установки:

```bash
nano /etc/teleproxy/config.toml
systemctl reload teleproxy
```

После установки управление сервисом:

```bash
systemctl status teleproxy       # статус
systemctl reload teleproxy       # перезагрузка конфига
nano /etc/teleproxy/config.toml  # редактирование конфига
```

Удаление:

```bash
curl -sSL https://raw.githubusercontent.com/teleproxy/teleproxy/main/install.sh | sh -s -- --uninstall
```

## Обновление

Для обновления до последней версии просто запустите скрипт установки повторно:

```bash
curl -sSL https://raw.githubusercontent.com/teleproxy/teleproxy/main/install.sh | sh
```

Скрипт заменит бинарник и перезапустит сервис. Существующий конфиг (`/etc/teleproxy/config.toml`) — секреты, порты, домен — сохраняется.

Для установки конкретной версии:

```bash
curl -sSL https://raw.githubusercontent.com/teleproxy/teleproxy/main/install.sh | TELEPROXY_VERSION=1.2.3 sh
```

## Готовый бинарник (любой Linux)

Статически собранные бинарники публикуются с каждым релизом — линковка с musl libc, никаких зависимостей. Скачайте и запускайте.

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

Контрольные суммы SHA256 публикуются вместе с каждым релизом.

## Docker

Подробности в разделе [Docker Quick Start](../docker/index.md) — самый простой способ запустить Teleproxy одной командой с автоматической генерацией секретов.

## Сборка из исходников

Установите зависимости для сборки:

=== "Debian / Ubuntu"

    ```bash
    apt install git curl build-essential libssl-dev zlib1g-dev
    ```

=== "CentOS / RHEL"

    ```bash
    yum groupinstall "Development Tools"
    yum install openssl-devel zlib-devel
    ```

=== "macOS (разработка)"

    ```bash
    brew install epoll-shim openssl
    ```

    Сборка под macOS использует [epoll-shim](https://github.com/jiixyj/epoll-shim) для эмуляции Linux epoll через kqueue, и Homebrew OpenSSL. Предназначено для локальной разработки — в продакшене используйте Linux.

Клонируйте репозиторий и соберите:

```bash
git clone https://github.com/teleproxy/teleproxy
cd teleproxy
make
```

Скомпилированный бинарник будет находиться по пути `objs/bin/teleproxy`.

!!! note
    Если сборка завершилась ошибкой, выполните `make clean` перед повторной попыткой.
