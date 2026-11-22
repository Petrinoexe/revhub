# revhub

Мини-панель для сети «хаб + выходные»: выходные сами инициируют туннель до
хаба, а хаб раздаёт через них клиентский трафик. VLESS на вход, VLESS /
WireGuard / обратный WireGuard — на транспорт между узлами.

Не форк 3x-ui. Модель данных — единственный источник конфигов: панель рендерит
артефакты, проверяет их `xray -test` и применяет с откатом.

## Что умеет

**Панель**
- вход по паролю (PBKDF2-HMAC-SHA256, подписанная cookie, лимит попыток);
  подписка `/sub/<token>` остаётся публичной — клиенты обновляют её сами;
- карточный UI без горизонтального скролла, тёмная тема, без сборки и CDN.

**Клиенты**
- VLESS-инбаунды: `tcp`, `ws`, `xhttp`; security — `tls` или `reality`;
- TLS: `acme` по домену, `acmeip` — сертификат Let's Encrypt на голый IP
  (shortlived, ~6 дней), `selfsigned` на IP с пином, `file` — свои файлы;
- UUID, срок, квота, привязка к инбаундам, подписка `/sub/<token>`.

**Узлы и туннели**
- `wg` (прямой), `wg-reverse` (выходной за NAT), `vless`;
- добавление хоста по SSH (пароль или ключ): панель сама ставит ядро и
  wireguard, кладёт файлы, применяет и **проверяет** результат на узле;
- мониторинг раз в 20 с: живой ли SSH, задержка, возраст handshake WG,
  через что ходим — `tunnel` или `direct`;
- управление сначала по WG-туннелю, напрямую — только если туннель лёг.

**Маршрутизация**
- упорядоченные правила (user / inbound / domain / ip / port / network) →
  `direct`, `block` или `tun:<имя>`; первый матч выигрывает;
- dry-run: «этот клиент с таким доменом пойдёт туда, и вот какие правила выше
  могут его перехватить».

## Установка

Одна команда, дальше только вопросы — как у 3x-ui, но без меню:

```bash
curl -fsSL https://raw.githubusercontent.com/Petrinoexe/revhub/master/install.sh | bash
```

Скрипт спросит всего четыре вещи (Enter — согласиться с предложенным):

1. **публичный IP** — определит сам и покажет на подтверждение;
2. **порт панели** (по умолчанию 2096);
3. **TLS панели**: домен через Let's Encrypt · IP через Let's Encrypt ·
   самоподписанный на IP · без TLS (панель только с localhost);
4. подтверждение.

Панель ставится **пустой**: в состоянии только карточка этого хоста —
инбаунды, туннели, клиентов и правила добавляешь в UI.

Дальше делает всё сам: зависимости (`curl`, `ca-certificates`, `wireguard-tools`,
`nftables`), ядро xray, сертификат, состояние, админа и первого клиента,
systemd-юнит, запуск сервиса. В конце печатает **адрес входа, логин и пароль**
(и пин сертификата, если он самоподписанный).

Бинарь не скачивается из релиза, а собирается на месте: скрипт делает
`git clone` репозитория и `go build` (Go поставит сам, если его нет — это ~200 МБ
и минута). Нужны только `git`, `curl` и root. Повторный запуск безопасен:
состояние и пароль не перетираются.

Репозиторий приватный, поэтому клону нужны креды — либо запускай установщик из
готового клона (`sudo bash install.sh`), либо передай адрес с доступом:
`REVHUB_GIT_URL=git@github.com:Petrinoexe/revhub.git` (SSH-ключ) или
`REVHUB_GIT_URL=https://<token>@github.com/Petrinoexe/revhub.git` (токен).
Ещё можно подложить готовый бинарь: `REVHUB_LOCAL_BIN=./revhub`.

| TLS | Что нужно | Кому подходит |
|---|---|---|
| домен | домен + свободный :80 (HTTP-01) или DNS-01 с токеном провайдера | постоянный узел с доменом |
| IP (Let's Encrypt) | публичный IP + **постоянно** свободный :80 | узел без домена, но с открытым 80 |
| IP (самоподписанный) | ничего | узел за NAT или с закрытым 80 (клиенту `allowInsecure`/пин) |
| без TLS | ничего | панель только через `ssh -L`, VLESS виден DPI |

`make release` → `dist/revhub-linux-{amd64,arm64,armv7}` собирает артефакты
локально (для релиза на GitHub), но установщику они больше не нужны.
Автоматизация без вопросов: `revhub install --host … --tls … --panel-tls`
(см. раздел CLI) — это тот же движок, который вызывает `install.sh`.


Ключи `revhub install` (нужны для автоматизации, интерактивный установщик
вызывает их сам): `--panel-tls` (HTTPS для панели), `--with-inbound` (создать
стартовый VLESS-инбаунд и клиента; по умолчанию панель пустая), `--port`
(порт VLESS, только вместе с `--with-inbound`),
`--acme http|dns|off`, `--acme-http-port`, `--cert/--key` (свои файлы),
`--dry-run` (файлы писать, системные команды не выполнять), `--no-apply`,
`--skip-packages`, `--print-password`.

## Локальная сборка (разработка)

```bash
make build                                   # ./revhub
./revhub demo --state demo-state.json        # демо: хаб + выходной, TLS по IP
./revhub serve --state demo-state.json       # http://127.0.0.1:2096
./revhub passwd --state demo-state.json      # пароль панели (спросит дважды)
./revhub serve --noauth                      # UI без пароля, только loopback
make verify                                  # render + xray -test по всем узлам
make test                                    # go test ./...
```

Нужен Go 1.26+ для сборки (так требует `golang.org/x/crypto` в SSH-клиенте);
сам бинарь статический, зависимостей нет.

## CLI

```
revhub serve    [--addr 127.0.0.1:2096] [--state state.json] [--out out]
                [--noauth] [--tls-cert FILE --tls-key FILE]
revhub install  --host <ip|домен> [--tls domain|ip-le|ip|reality|none]
                [--domain d] [--email e] [--panel-tls] [--dry-run]
revhub tls selfsigned --hosts ip[,домен] [--out DIR] [--days N]
revhub tls info       --cert FILE [--json]
revhub tls acme       --domain d --email e [--method http|dns] [--dns dns_cf]
revhub passwd   [--state state.json] [--user admin] [--random --password-file f]
revhub render   --node <id> [--state state.json] [--out out]
revhub validate [--state state.json]
revhub demo     [--state demo-state.json]
revhub version
```

## Документы

- `docs/ARCHITECTURE.md` — две плоскости (xray и ядро), клей через fwmark,
  конвейер применения, управление узлами по SSH.
- `docs/DECISIONS.md` — принятые решения и их цена (ADR-1…ADR-13).
- `docs/DATA-MODEL.md` — сущности, поля TLS и инварианты.
- `docs/ROADMAP.md` — что сделано и что следующее.

## Чего пока нет

- мультиадмин и роли: один админ;
- отзыв сессии = смена пароля (списка сессий нет);
- ротация ключа хоста SSH из UI (TOFU: первый ключ запоминается);
- hot-reload сертификата: продление ACME перезапускает xray;
- биллинг, Telegram-бот, «все протоколы как в 3x-ui» — сознательно.
