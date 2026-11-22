#!/usr/bin/env bash
# release.sh — собрать артефакты и опубликовать релиз revhub на GitHub.
#
#   GITHUB_TOKEN=ghp_... ./release.sh v0.1.0
#
# Токен берётся только из окружения и никуда не пишется: ни в файлы, ни в лог,
# ни в .git/config (пуш авторизуется заголовком через переменные окружения).
# Ввести без следа в истории шелла:
#   read -rsp 'GITHUB_TOKEN: ' GITHUB_TOKEN && export GITHUB_TOKEN
# Нужны права contents:write (классический токен — галочка repo / fine-grained —
# Contents: Read and write).
#
# Что делает: make release с версией тега → коммит тега и пуш (если нужно) →
# релиз через API с текстом из docs/RELEASE-<tag>.md → загрузка четырёх
# ассетов → проверка, что ссылка из install.sh отдаёт 200.
#
#   --dry-run    показать план, ничего не менять и не обращаться к API
#   --no-push    не пушить тег/ветку (например, уже запушено)
#   --draft      создать релиз как черновик

set -euo pipefail

TAG="${1:-}"
DRY=0
PUSH=1
DRAFT=0
for a in "$@"; do
  case "$a" in
    --dry-run) DRY=1;;
    --no-push) PUSH=0;;
    --draft)   DRAFT=1;;
  esac
done
[ -n "$TAG" ] && [[ "$TAG" != --* ]] || { echo "использование: GITHUB_TOKEN=... $0 v0.1.0 [--dry-run] [--no-push] [--draft]" >&2; exit 2; }

say()  { printf '%s\n' "$*"; }
ok()   { printf '\033[32m✓\033[0m %s\n' "$*"; }
die()  { printf '\033[31m✗\033[0m %s\n' "$*" >&2; exit 1; }
step() { printf '\n\033[1m%s\033[0m\n' "$*"; }


# go часто стоит не в PATH (например ~/soft/go/bin): находим сами, иначе make
# падает с невнятным "/bin/sh: 1: go: not found".
ensure_go() {
  if command -v go >/dev/null 2>&1; then return 0; fi
  local cand
  for cand in "$HOME/soft/go/bin" /usr/local/go/bin /usr/lib/go/bin /opt/go/bin /snap/bin; do
    if [ -x "$cand/go" ]; then
      export PATH="$cand:$PATH"
      say "go найден вне PATH: $cand/go — добавил в PATH только на время этого запуска"
      return 0
    fi
  done
  for cand in "$HOME"/sdk/go*/bin; do
    if [ -x "$cand/go" ]; then
      export PATH="$cand:$PATH"
      say "go найден: $cand/go"
      return 0
    fi
  done
  return 1
}

# --- репозиторий и токен
REPO_URL="$(git remote get-url origin 2>/dev/null || true)"
[ -n "$REPO_URL" ] || die "нет git remote origin"
SLUG="$(printf '%s' "$REPO_URL" | sed -E 's#.*github\.com[:/]([^/]+/[^/.]+)(\.git)?$#\1#')"
[[ "$SLUG" == */* ]] || die "не разобрал репозиторий из $REPO_URL"
TOKEN="${GITHUB_TOKEN:-${GH_TOKEN:-}}"

step "релиз $TAG в $SLUG"
[ "$DRY" = 1 ] && say "(dry-run: только план)"


# --- предполётная проверка прав: лучше узнать про 403 сейчас, чем на загрузке
if [ -z "$TOKEN" ] && [ "$DRY" != 1 ]; then
  die "нужен токен: GITHUB_TOKEN=... $0 $TAG (права contents:write)"
fi
if [ "$DRY" != 1 ]; then
  perms="$(curl -fsS -H "Authorization: Bearer $TOKEN" \
      -H "Accept: application/vnd.github+json" \
      "https://api.github.com/repos/$SLUG" 2>/dev/null \
    | python3 -c 'import json,sys; p=json.load(sys.stdin).get("permissions",{}); print("push" if p.get("push") else "no-push")' 2>/dev/null || echo "no-access")"
  case "$perms" in
    push) ok "токен видит $SLUG и имеет право записи";;
    no-push) die "токен видит репозиторий, но без права записи: нужен Contents: Read and write (fine-grained) или scope repo (classic)";;
    *) die "токен не даёт доступа к $SLUG: проверь Resource owner/Repository access (fine-grained) или scope repo (classic)";;
  esac
fi

# --- чистота дерева и статус ветки
BRANCH="$(git rev-parse --abbrev-ref HEAD)"
if [ -n "$(git status --porcelain)" ]; then
  say "! в рабочем дереве есть изменения — они попадут только в артефакты, не в тег"
fi
say "ветка: $BRANCH, коммит: $(git rev-parse --short HEAD)"

# --- артефакты
step "1/4 сборка артефактов (make release VERSION=$TAG)"
if [ "$DRY" = 1 ]; then
  say "  [dry-run] make release VERSION=$TAG"
else
  ensure_go || die "не нашёл go: поставь Go 1.26+ или добавь его в PATH
  (например: export PATH=\$HOME/soft/go/bin:\$PATH)
  готовые бинари можно взять из dist/ и загрузить в релиз вручную"
  say "go: $(go version)"
fi
if [ "$DRY" != 1 ]; then
  make release VERSION="$TAG"
fi
ASSETS=(dist/revhub-linux-amd64 dist/revhub-linux-arm64 dist/revhub-linux-armv7 dist/SHA256SUMS)
for f in "${ASSETS[@]}"; do
  [ "$DRY" = 1 ] || [ -f "$f" ] || die "нет файла $f"
done
ok "артефакты: ${ASSETS[*]}"

# --- тег
step "2/4 тег $TAG"
NOTES="docs/RELEASE-${TAG}.md"
[ -f "$NOTES" ] || NOTES=""
if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
  say "тег уже есть локально"
else
  if [ "$DRY" = 1 ]; then say "  [dry-run] git tag -a $TAG -m 'revhub $TAG'"; else
    git tag -a "$TAG" -m "revhub $TAG"
    ok "тег создан на $(git rev-parse --short HEAD)"
  fi
fi
# git push авторизуем тем же токеном, но без записи в .git/config и в URL:
# заголовок передаётся через переменные окружения, поэтому токена нет ни в ps,
# ни в истории git.
push_with_token() {
  if [ -z "$TOKEN" ]; then
    git push origin "$@"
    return
  fi
  local b64
  b64="$(printf 'x-access-token:%s' "$TOKEN" | base64 | tr -d '\n')"
  GIT_CONFIG_COUNT=1 \
  GIT_CONFIG_KEY_0="http.https://github.com/.extraheader" \
  GIT_CONFIG_VALUE_0="AUTHORIZATION: basic $b64" \
    git push origin "$@"
}

if [ "$PUSH" = 1 ]; then
  if [ "$DRY" = 1 ]; then say "  [dry-run] git push origin $BRANCH и git push origin $TAG"; else
    push_with_token "$BRANCH"
    push_with_token "$TAG"
    ok "ветка и тег запушены"
  fi
fi

# --- релиз
step "3/4 создание релиза"
BODY=""
if [ -n "$NOTES" ]; then
  BODY="$(python3 - "$NOTES" <<'PY'
import json,sys
print(json.dumps(open(sys.argv[1], encoding='utf-8').read()))
PY
)"
else
  BODY="\"revhub $TAG\""
fi
API="https://api.github.com/repos/$SLUG/releases"
PAYLOAD="{\"tag_name\":\"$TAG\",\"name\":\"revhub $TAG\",\"body\":$BODY,\"draft\":$([ "$DRAFT" = 1 ] && echo true || echo false),\"prerelease\":false}"

if [ "$DRY" = 1 ]; then
  say "  [dry-run] POST $API"
  say "  [dry-run] тело: ${PAYLOAD:0:160}…"
  REL_ID=""
else
  RESP="$(curl -fsS -X POST -H "Authorization: Bearer $TOKEN" \
      -H "Accept: application/vnd.github+json" \
      -d "$PAYLOAD" "$API")" || die "API отказал (проверь права токена contents:write)"
  REL_ID="$(printf '%s' "$RESP" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"
  UPLOAD_URL="$(printf '%s' "$RESP" | python3 -c 'import json,sys; print(json.load(sys.stdin)["upload_url"])' | sed 's/{?name,label}.*//')"
  HTML="$(printf '%s' "$RESP" | python3 -c 'import json,sys; print(json.load(sys.stdin)["html_url"])')"
  ok "релиз создан: $HTML"
fi

# --- ассеты
step "4/4 загрузка файлов"
for f in "${ASSETS[@]}"; do
  name="$(basename "$f")"
  if [ "$DRY" = 1 ]; then
    say "  [dry-run] загрузил бы $name ($(du -h "$f" 2>/dev/null | cut -f1 || echo '?'))"
    continue
  fi
  code="$(curl -s -o /tmp/revhub-upload.json -w '%{http_code}' -X POST \
      -H "Authorization: Bearer $TOKEN" \
      -H "Content-Type: application/octet-stream" \
      --data-binary "@$f" "$UPLOAD_URL?name=$name")"
  if [ "$code" = "201" ]; then ok "$name загружен"; else die "$name: HTTP $code ($(head -c 200 /tmp/revhub-upload.json))"; fi
done

# --- проверка того, что использует install.sh
step "проверка"
URL="https://github.com/$SLUG/releases/latest/download/revhub-linux-amd64"
if [ "$DRY" = 1 ]; then say "  [dry-run] GET $URL"; else
  code="$(curl -s -o /dev/null -w '%{http_code}' -L "$URL")"
  [ "$code" = "200" ] || die "ассет не отдаётся ($code): $URL"
  ok "install.sh увидит релиз: $URL → 200"
  say ""
  say "установка одной командой:"
  say "  curl -fsSL https://raw.githubusercontent.com/$SLUG/$BRANCH/install.sh | bash"
fi
