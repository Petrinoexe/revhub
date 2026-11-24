# Модель данных

Состояние — один JSON-документ (`state.json`), версия 1. Всё, что попадает в
конфиги, есть здесь и только здесь.

## Node — узел сети

| Поле | Смысл |
|---|---|
| `id` | стабильный идентификатор (slug) |
| `name` | человеческое имя |
| `role` | `entry` \| `exit` \| `both` |
| `public_addr` | `host:port` для подписок и Endpoint'ов |
| `core` | имя сервиса ядра (`xray`), если отличается |

## Inbound — приём клиентов (только VLESS в MVP)

| Поле | Смысл |
|---|---|
| `id`, `node_id`, `tag` | идентификаторы; `tag` попадает в конфиг и в правила |
| `kind` | `vless` |
| `listen`, `port` | адрес прослушивания |
| `transport` | `tcp` \| `ws` \| `xhttp` |
| `security` | `reality` \| `tls` \| `none` |
| `sni`, `dest` | для reality: маскировочный домен и куда fallback'ить |
| `private_key`, `public_key`, `short_id` | ключи reality (генерирует панель) |
| `path` | для ws/xhttp |
| `flow` | `xtls-rprx-vision` только для reality+tcp |
| `security` | `tls` (по умолчанию) \| `reality` \| `none` |
| `cert_source` | `acme` (домен) \| `acmeip` (IP через Let's Encrypt) \| `selfsigned` (IP без CA) \| `file` (готовые файлы) |
| `domain`, `ip` | два разных поля: домен для acme/SNI, IP — для самоподписанного |
| `cert_file`, `key_file` | итоговые пути на узле (`/etc/revhub/tls/...`) |
| `wireguard.subnet` | подсеть клиентов (`10.88.0.0/24` по умолчанию), `.1` — сам Xray |
| `wireguard.dns` | DNS для клиентских `.conf` (IP через запятую, по умолчанию `1.1.1.1, 1.0.0.1`) |
| `wireguard.private_key`, `public_key` | ключи сервера WireGuard (генерирует панель) |

## Tunnel — транспорт до другого узла

| Поле | Смысл |
|---|---|
| `id`, `name` | идентификаторы; `name` даёт тег `tun:<name>` |
| `kind` | `wg` \| `wg-reverse` \| `vless` |
| `from_node_id`, `to_node_id` | ближний и дальний концы |
| `subnet` | `/30` на туннель, `.1` — from, `.2` — to |
| `listen_port`, `keepalive` | WG |
| `key_from_private/public`, `key_to_private/public` | ключи WG (генерирует панель) |
| `mark` | метка для маршрутизации в этот туннель (уникальна на узле) |
| `uuid`, `transport`, `sni`, `public_key`, `short_id`, `path`, `flow` | для `vless` |
| `enabled` | выключенный туннель не рендерится и его правила не применяются |

## Client — пользователь

| Поле | Смысл |
|---|---|
| `id`, `email` | `email` = метка в статистике xray и в правилах по `user` |
| `uuid` | VLESS |
| `enabled` | выключенный не попадает ни в конфиг, ни в подписку |
| `expires_at`, `quota_gb` | срок и квота; `0`/пусто = без ограничения |
| `inbounds` | список inbound-id, к которым привязан (аналог client_inbounds) |
| `wireguard` | карта `inbound-id → {address, private_key, public_key, preshared_key}`; заполняется при сохранении, уходит в подписку и в клиентский `.conf` |
| `sub_token` | секрет URL подписки |

## Rule — правило маршрутизации

Порядок в массиве = приоритет. Первый матч выигрывает.

| Поле | Смысл |
|---|---|
| `id`, `name` | |
| `node_id` | `""` = правило общее для всех узлов |
| `enabled` | выключенное не рендерится (и в UI помечено «не действует») |
| `user`, `inbound`, `domain`, `ip`, `port`, `network` | условия; пустое = не проверяется |
| `outbound` | `direct` \| `block` \| `tun:<name>` |

Домены понимают префиксы xray: `full:`, `domain:`, `regexp:`, `geosite:`
(без префикса — подстрока, как в xray). IP — CIDR, `geoip:` или литерал.

## Инварианты (проверяются при сохранении и при рендере)

1. `tag` инбаунда уникален в пределах узла; `name` туннеля уникально.
2. `mark` уникален в пределах узла, не 0.
3. У каждого туннеля заполнены ключи для своего `kind`; `subnet` валиден /30.
4. Каждое правило ссылается на существующий на этом узле тег исходящего.
5. У инбаунда с `security=reality` заполнены `private_key`, `short_id`, `dest`.
6. Клиент с непустым `inbounds` не может ссылаться на инбаунд чужого узла.
7. `security=tls` требует `cert_source`: `acme` — непустой `domain`,
   `acmeip` — непустой `ip`, `selfsigned` — `ip` (или `domain`), `file` — оба файла.
