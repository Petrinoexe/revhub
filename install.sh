#!/usr/bin/env bash
# revhub — установщик. Запускается без аргументов и всё спрашивает сам:
#
#   curl -fsSL https://raw.githubusercontent.com/Petrinoexe/revhub/master/install.sh | bash
#
# Что делает: определяет IP машины, ставит зависимости, клонирует репозиторий и
# собирает бинарь,
# настраивает TLS (домен / IP / самоподписанный), поднимает сервис панели и
# печатает креды и адрес входа.
#
# Служебные переменные (обычному пользователю не нужны):
#   REVHUB_REPO=owner/name      репозиторий для клона (по умолчанию Petrinoexe/revhub)
#   REVHUB_GIT_URL=<url>        свой адрес клона (например git@github.com:…)
#   REVHUB_BRANCH=master        ветка
#   REVHUB_TEST_ROOT=/tmp/x     писать всё в песочницу, без systemd (для автотестов)
#   REVHUB_LOCAL_BIN=/path      взять готовый бинарь вместо скачивания/сборки

set -euo pipefail

REPO="${REVHUB_REPO:-Petrinoexe/revhub}"
TEST_ROOT="${REVHUB_TEST_ROOT:-}"
LOCAL_BIN="${REVHUB_LOCAL_BIN:-}"
GO_VER="${REVHUB_GO_VERSION:-1.27.4}"

C_OK=$'\033[32m'; C_WARN=$'\033[33m'; C_ERR=$'\033[31m'; C_B=$'\033[1m'; C_OFF=$'\033[0m'
say()  { printf '%s\n' "$*"; }
ok()   { printf '%s✓%s %s\n' "$C_OK" "$C_OFF" "$*"; }
warn() { printf '%s!%s %s\n' "$C_WARN" "$C_OFF" "$*"; }
die()  { printf '%s✗%s %s\n' "$C_ERR" "$C_OFF" "$*" >&2; exit 1; }
hdr()  { printf '\n%s%s%s\n' "$C_B" "$*" "$C_OFF"; }

# ------------------------------------------------------------------ окружение

if [ -n "$TEST_ROOT" ]; then
  PREFIX="$TEST_ROOT/usr/local"
  ETCDIR="$TEST_ROOT/etc/revhub"
  STATEDIR="$TEST_ROOT/var/lib/revhub"
  UNITDIR="$TEST_ROOT/systemd"
  GOROOT_DIR="$TEST_ROOT/usr/local"
  SANDBOX=1
else
  PREFIX="/usr/local"
  ETCDIR="/etc/revhub"
  STATEDIR="/var/lib/revhub"
  UNITDIR="/etc/systemd/system"
  GOROOT_DIR="/usr/local"
  SANDBOX=0
  [ "$(id -u)" = "0" ] || die "нужен root: sudo bash install.sh"
fi

[ "$(uname -s)" = "Linux" ] || die "поддерживается только Linux"
case "$(uname -m)" in
  x86_64|amd64)  ARCH=amd64; GARCH=amd64;;
  aarch64|arm64) ARCH=arm64; GARCH=arm64;;
  armv7l|armv7)  ARCH=armv7; GARCH=armv6l;;
  *) die "неизвестная архитектура: $(uname -m)";;
esac

# При «curl … | bash» stdin занят текстом скрипта: ответы читаем с терминала
# (/dev/tty), иначе read съел бы следующие строки установщика. В песочнице и в
# автотестах читаем stdin — там ответы подаются пайпом.
if [ "$SANDBOX" = 1 ] || [ "${REVHUB_ANSWERS_ON_STDIN:-0}" = 1 ]; then
  READ_SRC="/dev/stdin"
else
  READ_SRC="/dev/tty"
  { : <"$READ_SRC"; } 2>/dev/null || { READ_SRC="/dev/stdin"; warn "нет терминала — беру значения по умолчанию"; }
fi

BIN="$PREFIX/bin/revhub"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

hdr "revhub installer"
say "система:  $(uname -s) $(uname -m) → $ARCH"
say "каталоги: $PREFIX/bin, $ETCDIR, $STATEDIR"
[ "$SANDBOX" = 1 ] && warn "тестовый режим: пишу в $TEST_ROOT, systemd не трогаю"

# ------------------------------------------------------------------ вопросы

STEP=0
TOTAL=4
sec() { STEP=$((STEP + 1)); hdr "$STEP/$TOTAL $*"; }

# ask «вопрос» «значение по умолчанию» → ответ в stdout (приглашение в stderr)
ask() {
  local prompt="$1" def="${2:-}" ans=""
  if [ -n "$def" ]; then printf '%s%s%s [%s]: ' "$C_B" "$prompt" "$C_OFF" "$def" >&2
  else printf '%s%s%s: ' "$C_B" "$prompt" "$C_OFF" >&2; fi
  read -r ans <"$READ_SRC" || true
  printf '%s' "${ans:-$def}"
}

REINSTALL=0
UPDATE=0
if [ -f "$ETCDIR/state.json" ] || [ -f "$ETCDIR/credentials.json" ] || [ -f "$ETCDIR/revhub.service" ]; then
  TOTAL=5
  sec "панель уже установлена"
  say "  найдено: $ETCDIR"
  say "  1) обновить бинарь без изменения настроек"
  say "  2) полная переустановка (узлы и пароли будут удалены)"
  say "  3) отмена"
  ANS="$(ask 'Выбор' '1')"
  case "$ANS" in
    1) UPDATE=1; ok "обновление без изменения настроек";;
    2) warn "полная переустановка стирает узлы, туннели, клиентов и все пароли"
       ANS="$(ask 'Подтвердить переустановку с нуля? (y/N)' 'n')"
       case "$ANS" in y|Y|yes|Yes) REINSTALL=1;; *) die "переустановка отменена";; esac;;
    *) die "отменено; настройки не изменены";;
  esac
fi

if [ "$UPDATE" = 0 ]; then
sec "адрес машины"
detect_ip() {
  local url ip
  for url in https://api.ipify.org https://ifconfig.me/ip https://icanhazip.com; do
    ip="$(curl -fsS --max-time 6 "$url" 2>/dev/null | tr -d '[:space:]' || true)"
    case "$ip" in
      *[0-9].[0-9]*) printf '%s' "$ip"; return 0;;
    esac
  done
  ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  [ -n "$ip" ] && printf '%s' "$ip"
}
PUB_IP="${PUB_IP:-$(detect_ip || true)}"
[ -n "$PUB_IP" ] || PUB_IP="$(ask 'не смог определить публичный IP. Введи его' '')"
[ -n "$PUB_IP" ] || die "без IP дальше нельзя"
IP_CONFIRM="$(ask "Публичный IP этой машины — $PUB_IP. Верно? (y/n)" "y")"
if [ "$IP_CONFIRM" != "y" ]; then
  PUB_IP="$(ask 'Введи публичный IP' "$PUB_IP")"
fi
ok "IP: $PUB_IP"

sec "порт панели"
PANEL_PORT="$(ask 'Порт панели' '2096')"
case "$PANEL_PORT" in *[!0-9]*) die "порт должен быть числом";; esac

sec "TLS панели"
say "  1) домен   — сертификат Let's Encrypt (нужен открытый порт 80)"
say "  2) IP      — сертификат Let's Encrypt (порт 80, ~6 дней, продлевается сам)"
say "  3) IP      — самоподписанный (ничего не нужно, браузер предупредит)"
say "  4) без TLS — панель только с этой машины (через ssh -L)"
TLS_CHOICE="$(ask 'Выбор' '1')"
PANEL_TLS=1
ADMIN_EMAIL=""
DOMAIN=""
case "$TLS_CHOICE" in
  1)
    DOMAIN="$(ask 'Домен (A-запись уже должна указывать на этот сервер)' '')"
    [ -n "$DOMAIN" ] || die "без домена вариант 1 не работает; выбери 2 или 3"
    ADMIN_EMAIL="$(ask "E-mail для Let's Encrypt" "admin@$DOMAIN")"
    MODE=domain; HOST="$DOMAIN"
    ;;
  2)
    ADMIN_EMAIL="$(ask "E-mail для Let's Encrypt" "admin@$PUB_IP")"
    MODE=ip-le; HOST="$PUB_IP"
    warn "порт 80 должен быть свободен и доступен из интернета — Let's Encrypt проверяет по HTTP-01"
    ;;
  3)
    MODE=ip; HOST="$PUB_IP"
    warn "клиенты увидят предупреждение, пока не доверят сертификат (пин покажу в конце)"
    ;;
  4)
    MODE=none; HOST="$PUB_IP"; PANEL_TLS=0
    warn "панель будет доступна только с localhost; входить через: ssh -L $PANEL_PORT:127.0.0.1:$PANEL_PORT root@$PUB_IP"
    ;;
  *) die "выбор 1–4";;
esac

if [ "$PANEL_TLS" = 1 ]; then PANEL_ADDR="0.0.0.0:$PANEL_PORT"; else PANEL_ADDR="127.0.0.1:$PANEL_PORT"; fi

sec "что будет сделано"
say "  панель:    $( [ "$PANEL_TLS" = 1 ] && echo "https" || echo "http" )://$( [ "$PANEL_TLS" = 1 ] && echo "$HOST" || echo "127.0.0.1" ):$PANEL_PORT"
say "  TLS:       $MODE"
say "  состояние: $ETCDIR/state.json, артефакты: $STATEDIR/out"
say "  панель ставится пустой: узлы, инбаунды, туннели и клиентов добавишь в UI"
CONFIRM="$(ask 'Ставим? (y/n)' 'y')"
[ "$CONFIRM" = "y" ] || die "отменено"
fi

# ------------------------------------------------------------------ зависимости

hdr "5/5 установка"

PKG=""
command -v apt-get >/dev/null 2>&1 && PKG=apt
command -v dnf     >/dev/null 2>&1 && PKG=dnf
command -v yum     >/dev/null 2>&1 && PKG=yum
command -v apk     >/dev/null 2>&1 && PKG=apk

pkg_install() {
  [ -n "$PKG" ] || { warn "неизвестный пакетный менеджер, поставь вручную: $*"; return 0; }

  case "$PKG" in
    apt) DEBIAN_FRONTEND=noninteractive apt-get update -qq
         DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" ;;
    dnf) dnf install -y -q "$@" ;;
    yum) yum install -y -q "$@" ;;
    apk) apk add --no-cache "$@" ;;
  esac
}

if [ "$SANDBOX" = 0 ]; then
  need=""
  for c in curl tar unzip; do command -v "$c" >/dev/null 2>&1 || need="$need $c"; done
  [ -f /etc/ssl/certs/ca-certificates.crt ] || need="$need ca-certificates"
  command -v wg-quick >/dev/null 2>&1 || need="$need wireguard-tools"
  command -v dnsmasq >/dev/null 2>&1 || need="$need dnsmasq"
  command -v nft >/dev/null 2>&1 || command -v iptables >/dev/null 2>&1 || need="$need nftables"
  command -v git >/dev/null 2>&1 || need="$need git"
  if [ -n "${need// /}" ]; then
    say "ставлю:$need"
    pkg_install $need
  fi
  ok "зависимости на месте"
else
  warn "тестовый режим: пакеты не ставлю"
fi

# ------------------------------------------------------------------ бинарь
# Никаких релизов: всегда клон репозитория и сборка. Так установка не зависит от
# того, опубликован ли релиз и приложены ли к нему ассеты.

GIT_URL="${REVHUB_GIT_URL:-https://github.com/$REPO.git}"
BRANCH="${REVHUB_BRANCH:-master}"

ensure_go() {
  command -v go >/dev/null 2>&1 && return 0
  local c
  for c in "$HOME/soft/go/bin" /usr/local/go/bin /usr/lib/go/bin /opt/go/bin "$GOROOT_DIR/go/bin"; do
    [ -x "$c/go" ] && { export PATH="$c:$PATH"; ok "go найден: $c/go"; return 0; }
  done
  return 1
}

install_go() {
  say "go не найден — ставлю Go $GO_VER"
  local tf="$TMP/go.tgz"
  curl -fsSL --retry 3 -o "$tf" "https://go.dev/dl/go${GO_VER}.linux-${GARCH}.tar.gz" \
    || die "не смог скачать Go $GO_VER"
  mkdir -p "$GOROOT_DIR"
  tar -C "$GOROOT_DIR" -xzf "$tf" || die "не смог распаковать Go"
  export PATH="$GOROOT_DIR/go/bin:$PATH"
  ok "Go: $(go version | awk '{print $3}')"
}

build_from_source() {
  ensure_go || install_go
  local src ver
  if [ -f go.mod ] && grep -q '^module revhub' go.mod 2>/dev/null; then
    src="$(pwd)"
    ok "исходники на месте: $src (клон не нужен)"
  else
    command -v git >/dev/null 2>&1 || die "для установки нужен git"
    src="$TMP/src"
    say "клоню $GIT_URL (ветка $BRANCH)"
    git clone --depth 1 --branch "$BRANCH" "$GIT_URL" "$src" \
      || die "git clone не удался: проверь адрес и доступ.
  приватный репозиторий читается только с кредами — либо
  REVHUB_GIT_URL=git@github.com:owner/name.git (SSH-ключ), либо
  REVHUB_GIT_URL=https://<token>@github.com/owner/name.git (токен),
  либо запусти установщик из готового клона: sudo bash install.sh"
    ok "склонировано: $(cd "$src" && git rev-parse --short HEAD)"
  fi
  # теги при --depth 1 не приходят: подтягиваем, чтобы версия была человеческой
  ( cd "$src" && git fetch --tags --depth 1 -q 2>/dev/null || true )
  ver="$(cd "$src" && git describe --tags --always 2>/dev/null || echo dev)"
  ( cd "$src" && CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X main.version=$ver" -o "$TMP/revhub" ./cmd/revhub ) \
    || die "сборка не удалась"
  ok "собрано: $("$TMP/revhub" version)"
}

say "собираю бинарь из исходников"
if [ -n "$LOCAL_BIN" ] && [ -f "$LOCAL_BIN" ]; then
  cp "$LOCAL_BIN" "$TMP/revhub"; chmod 755 "$TMP/revhub"
  ok "взят готовый бинарь: $LOCAL_BIN"
else
  build_from_source
fi

chmod 755 "$TMP/revhub"
ok "новый бинарь собран; установка после резервного копирования"

if [ "$UPDATE" = 1 ]; then
  MANAGE_SERVICE=1
  if [ "$SANDBOX" = 1 ] && [ "${REVHUB_TEST_SYSTEMCTL:-0}" != 1 ]; then MANAGE_SERVICE=0; fi
  [ -x "$BIN" ] || die "не найден текущий исполняемый бинарь $BIN"
  "$TMP/revhub" version >/dev/null || die "новый бинарь не запускается"
  if [ "$MANAGE_SERVICE" = 1 ]; then
    systemctl is-active --quiet revhub || die "служба revhub не активна; обновление отменено"
  fi
  BACKUP="$(mktemp -d "$ETCDIR/update-backup-XXXXXX")" || die "не удалось создать резервную копию"
  chmod 700 "$BACKUP"
  cp -p "$BIN" "$BACKUP/revhub" || die "не удалось сохранить старый бинарь"
  tar -C "$ETCDIR" --exclude='./backup-*' --exclude='./update-backup-*' -cf "$BACKUP/config.tar" . || die "не удалось сохранить настройки"
  if [ -f "$UNITDIR/revhub.service" ]; then cp -p "$UNITDIR/revhub.service" "$BACKUP/revhub.service" || die "не удалось сохранить unit"; fi
  NEWBIN="$(mktemp "$PREFIX/bin/.revhub-update-XXXXXX")" || die "не удалось подготовить бинарь"
  if ! install -m 755 "$TMP/revhub" "$NEWBIN" || ! mv -f "$NEWBIN" "$BIN"; then
    rm -f "$NEWBIN"
    die "не удалось заменить бинарь; старый бинарь сохранён: $BACKUP/revhub"
  fi
  if [ "$MANAGE_SERVICE" = 1 ]; then
    if ! systemctl restart revhub || ! sleep 4 || ! systemctl is-active --quiet revhub; then
      warn "новая версия не запустилась; восстанавливаю старый бинарь"
      ROLLBIN="$(mktemp "$PREFIX/bin/.revhub-rollback-XXXXXX")" || die "ошибка отката; бинарь: $BACKUP/revhub"
      if ! cp -p "$BACKUP/revhub" "$ROLLBIN" || ! mv -f "$ROLLBIN" "$BIN"; then
        die "ошибка восстановления бинаря; копия: $BACKUP/revhub"
      fi
      systemctl restart revhub && systemctl is-active --quiet revhub || die "старый бинарь восстановлен, но сервис не запустился: $BACKUP/revhub"
      die "обновление не удалось; старый бинарь восстановлен"
    fi
  fi
  ok "панель обновлена; настройки не изменялись"
  # Обновление меняет только бинарь: юнит xray, правило sudo и применённый
  # конфиг могли остаться от старой версии или отсутствовать вовсе. Досинхронизируем.
  if [ "$SANDBOX" != 1 ]; then
    if ! "$BIN" repair --prefix "$PREFIX" --etc-dir "$ETCDIR" --state-dir "$STATEDIR" --unit-dir "$UNITDIR"; then
      warn "панель обновлена, но системная часть не настроена (см. вывод выше)"
      die "не удалось применить системные изменения; состояние и пароль не тронуты"
    fi
    ok "системная часть синхронизирована: юнит xray, sudo, конфиг"
  fi
  say "  прежний бинарь: $BACKUP/revhub"
  exit 0
fi

# ------------------------------------------------------------------ настройка

ARGS=(install
  --host "$HOST"
  --panel-addr "$PANEL_ADDR"
  --prefix "$PREFIX"
  --etc-dir "$ETCDIR"
  --state-dir "$STATEDIR"
  --unit-dir "$UNITDIR"
  --tls "$MODE")
if [ "$REINSTALL" = 1 ]; then ARGS+=(--reinstall); fi
if [ -n "$ADMIN_EMAIL" ]; then ARGS+=(--email "$ADMIN_EMAIL"); fi
if [ -n "$DOMAIN" ]; then ARGS+=(--domain "$DOMAIN"); fi
if [ "$PANEL_TLS" = 1 ]; then ARGS+=(--panel-tls); fi
if [ "$SANDBOX" = 1 ]; then ARGS+=(--no-start --no-apply --skip-packages); fi

say ""
"$TMP/revhub" "${ARGS[@]}" || die "установка revhub install не удалась"

# ------------------------------------------------------------------ итог

PASS_FILE="$ETCDIR/initial-password"
PANEL_USER="admin"
PANEL_PASS="$(cat "$PASS_FILE" 2>/dev/null || echo '(уже был задан ранее — см. revhub passwd)')"
URL_SCHEME="http"; [ "$PANEL_TLS" = 1 ] && URL_SCHEME="https"
URL_HOST="$HOST"; [ "$PANEL_TLS" = 0 ] && URL_HOST="127.0.0.1"
URL="$URL_SCHEME://$URL_HOST:$PANEL_PORT"

PIN=""
if [ "$MODE" = "ip" ]; then
  PIN="$("$BIN" tls info --cert "$ETCDIR/tls/server.crt" 2>/dev/null | awk '/^пин:/ {print $2}')"
fi

hdr "готово"
if [ "$SANDBOX" = 1 ]; then
  say "  (тестовый режим: сервис не включён)"
else
  say "  сервис:   systemctl status revhub  (логи: journalctl -u revhub -f)"
fi
say "  панель:   $URL"
say "  логин:    $PANEL_USER"
say "  пароль:   $PANEL_PASS"
[ -n "$PIN" ] && say "  пин серт: $PIN"
say ""
say "  файлы:    $ETCDIR (состояние, пароль в initial-password 0600)"
say "  сменить пароль: $BIN passwd --state $ETCDIR/state.json"
if [ "$REINSTALL" = 1 ]; then
  say "  бэкап:    $(ls -d "$ETCDIR"/backup-* 2>/dev/null | tail -1) (state, credentials, secrets)"
fi
if [ "$MODE" = "ip-le" ] || [ "$MODE" = "domain" ]; then
  say "  сертификат продлевается сам (cron acme.sh); порт 80 должен оставаться открытым"
fi
