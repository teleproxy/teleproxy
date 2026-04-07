---
description: "Установите Teleproxy одной командой, скачайте бинарник вручную или соберите из исходников. Поддержка x86_64 и ARM64 на Linux."
---

# Установка

## Установка одной командой (рекомендуется) {#one-liner-install-recommended}

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

## RPM-репозиторий (RHEL, Rocky, Alma, Fedora)

Для RHEL 9, RHEL 10, AlmaLinux, Rocky Linux и Fedora 41/42 ставьте через dnf — обновления пойдут через пакетный менеджер:

```bash
dnf install https://teleproxy.github.io/repo/teleproxy-release-latest.noarch.rpm
dnf install teleproxy
systemctl enable --now teleproxy
```

При первой установке генерируется случайный секрет в `/etc/teleproxy/config.toml`, и пост-установочное сообщение печатает ссылку для подключения. Последующие `dnf upgrade` обновляют только бинарник и никогда не трогают ваш конфиг.

Репозиторий подписан ключом RSA 4096 с SHA-512 (совместим с rpm-sequoia в RHEL 9). Setup-пакет кладёт `/etc/yum.repos.d/teleproxy.repo` и публичный ключ в `/etc/pki/rpm-gpg/`.

Удаление:

```bash
dnf remove teleproxy
```

Файл `/etc/teleproxy/config.toml` остаётся на месте, чтобы при повторной установке всё подхватилось как было.

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
