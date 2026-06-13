# Jevio Unlocker for iOS

iOS-порт [`tg-proxy-android`](https://github.com/xVerdy1337/tg-proxy-android), локального
MTProto-прокси для обхода блокировок Telegram.

Проект поднимает прокси прямо на устройстве, принимает подключения Telegram через
`tg://proxy` на `127.0.0.1:1443` и пересылает MTProto-трафик к Telegram DC через
WebSocket/TLS (`/apiws`) с Fake TLS masking, Cloudflare fallback, route cache, TCP fallback
и реконнектом при смене сети.

Сторонний VPS не нужен: весь relay-движок работает локально в iOS Network Extension.

## Статус

Текущий статус: рабочая инженерная сборка до полевого теста на реальном iPhone.

Что уже сделано:

- портировано протокольное ядро из Android: MTProto handshake, Fake TLS, message splitter, AES-CTR;
- добавлены unit tests для детерминированного ядра;
- добавлен SwiftUI app для управления туннелем, секретом, Fake TLS domain и Telegram deeplink;
- добавлен Packet Tunnel Extension, который хостит локальный прокси в фоне;
- добавлен WebSocket transport:
  - direct Telegram web-front candidates через `Network.framework`;
  - Cloudflare candidates через `URLSessionWebSocketTask` с явным `/apiws`;
- добавлены route cache, TCP fallback, Fake TLS masking relay и сброс соединений при смене сети;
- GitHub Actions CI генерирует Xcode-проект, запускает `JevioCoreTests` и собирает app target без signing.

Что еще не подтверждено:

- запуск Packet Tunnel на реальном iPhone с настоящими Network Extension entitlement;
- доступ Telegram iOS к `127.0.0.1:1443` внутри выбранной tunnel-конфигурации;
- какой transport реально побеждает в разных сетях: direct, Cloudflare или TCP fallback;
- долгоживущая работа в фоне и реконнект при Wi-Fi/LTE переключении.

## Как это работает

```text
Telegram iOS
  |
  | tg://proxy server=127.0.0.1 port=1443 secret=...
  v
127.0.0.1:1443
MtProtoProxyServer inside PacketTunnel extension
  |
  | MTProto obfuscation + AES-CTR re-encryption
  v
Telegram DC transport
  |
  +-- WebSocket/TLS direct: kwsN.web.telegram.org /apiws
  +-- WebSocket/TLS Cloudflare fallback: kwsN.<cf-domain> /apiws
  +-- Raw TCP fallback: Telegram DC :443
```

На Android оригинальный проект держит локальный TCP-сервер через foreground service.
На iOS обычное приложение не может надежно держать такой сервер в фоне, поэтому здесь используется
`NEPacketTunnelProvider`. Он выступает контейнером живучести для локального proxy process.

## Основные возможности

- Локальный MTProto proxy на `127.0.0.1`.
- Telegram deeplink generation через `tg://proxy`.
- Fake TLS секреты формата `ee...`.
- Plain MTProto proxy секреты формата `dd...`.
- WebSocket relay через Telegram `/apiws`.
- Cloudflare-fronted fallback domains.
- Direct pinned-IP transport с сохранением TLS SNI.
- TCP fallback к raw Telegram DC `:443`.
- Route cache для быстрого reconnect.
- Reset активных сессий при смене сети через `NWPathMonitor`.
- Best-effort masking relay для невалидных Fake TLS probes.

## Структура проекта

| Путь | Назначение |
|---|---|
| `Sources/JevioCore` | Протокол, криптография, WebSocket/TCP relay, Fake TLS, MTProto parsing |
| `Sources/JevioUnlocker` | SwiftUI app: UI, настройки, секрет, Telegram deeplink, управление tunnel |
| `Sources/PacketTunnel` | `NEPacketTunnelProvider`, запуск локального прокси и network path monitoring |
| `Tests/JevioCoreTests` | Unit tests для protocol core |
| `docs/ARCHITECTURE.md` | Архитектура и жизненный цикл соединения |
| `docs/PORT_MAP.md` | Карта соответствия Android Kotlin файлов и iOS Swift файлов |
| `.github/workflows/build.yml` | CI: XcodeGen, unit tests, simulator build |
| `project.yml` | XcodeGen project definition |

## Требования

Для CI и симуляторной сборки:

- macOS runner или Mac;
- Xcode 16.x;
- XcodeGen;
- iOS Simulator.

Для запуска на реальном iPhone:

- Mac с Xcode;
- платный Apple Developer Program account;
- Network Extension entitlement;
- App Group capability;
- физическое устройство.

Важно: `com.apple.developer.networking.networkextension` недоступен на бесплатном Apple ID.
Без paid Apple Developer account Packet Tunnel на устройстве не запустится.

## Сборка на Mac

Установить XcodeGen:

```bash
brew install xcodegen
```

Сгенерировать Xcode project:

```bash
xcodegen generate
open JevioUnlocker.xcodeproj
```

Для локальной разработки без устройства можно запускать unit tests:

```bash
xcodebuild test \
  -project JevioUnlocker.xcodeproj \
  -scheme JevioUnlocker \
  -destination 'platform=iOS Simulator,name=iPhone 16,OS=latest' \
  -only-testing:JevioCoreTests \
  CODE_SIGNING_ALLOWED=NO
```

Для simulator build:

```bash
xcodebuild build \
  -project JevioUnlocker.xcodeproj \
  -scheme JevioUnlocker \
  -destination 'generic/platform=iOS Simulator' \
  CODE_SIGNING_ALLOWED=NO
```

## Настройка signing для iPhone

Перед запуском на устройстве нужно настроить Apple signing.

1. В `project.yml` указать свой `DEVELOPMENT_TEAM`.
2. В Apple Developer portal создать App ID для:
   - `com.jevio.unlocker`;
   - `com.jevio.unlocker.PacketTunnel`.
3. Включить capabilities:
   - App Groups;
   - Network Extensions.
4. Создать App Group:
   - `group.com.jevio.unlocker`.
5. Убедиться, что App Group указан и в app target, и в PacketTunnel target.
6. Перегенерировать проект:

```bash
xcodegen generate
```

## Использование

После установки на iPhone:

1. Открыть Jevio Unlocker.
2. Проверить или сгенерировать proxy secret.
3. При необходимости указать Fake TLS domain.
4. Запустить tunnel.
5. Нажать "Подключить Telegram".
6. В Telegram подтвердить добавление MTProto proxy.

По умолчанию используется:

- local host: `127.0.0.1`;
- local port: `1443`;
- App Group: `group.com.jevio.unlocker`;
- Fake TLS domain: `www.cloudflare.com`.

## CI

GitHub Actions workflow находится в `.github/workflows/build.yml`.

CI делает следующее:

1. запускается на `macos-15`;
2. печатает версии Xcode и XcodeGen;
3. устанавливает XcodeGen;
4. генерирует `JevioUnlocker.xcodeproj`;
5. печатает доступные iOS simulators;
6. запускает `JevioCoreTests`;
7. собирает приложение для iOS Simulator без code signing.

Последние workflow fixes:

- runner обновлен до `macos-15`, чтобы Xcode мог читать project format от свежего XcodeGen;
- simulator destination обновлен на `iPhone 16`;
- тесты больше не маскируются через `|| true`.

## Roadmap

### Phase 0: Repository foundation

Статус: done.

- Создать структуру XcodeGen проекта.
- Разделить app, extension и core framework.
- Добавить базовый SwiftUI UI.
- Добавить Packet Tunnel target.
- Добавить unit tests.
- Добавить GitHub Actions CI.

### Phase 1: Protocol parity with Android

Статус: mostly done, field validation pending.

- Портировать MTProto handshake.
- Портировать constants and DC mapping.
- Портировать Fake TLS.
- Портировать message splitter.
- Портировать AES-CTR streaming behavior.
- Добавить WebSocket `/apiws` transport.
- Добавить Cloudflare fallback.
- Добавить route cache.
- Добавить TCP fallback.
- Добавить Fake TLS masking relay.
- Сверить поведение с `tg-proxy-android` на реальном трафике.

### Phase 2: Build and CI hardening

Статус: done for simulator, device signing pending.

- Сделать CI fail-fast и без замаскированных ошибок.
- Починить XcodeGen/Xcode version compatibility.
- Починить simulator destination.
- Починить Swift compile errors под Xcode 16.
- Проверять unit tests и app build на каждом push.
- Добавить отдельный CI job для generated project validation, если понадобится.

### Phase 3: iPhone field test

Статус: pending, требует paid Apple Developer account.

- Настроить signing и entitlements.
- Установить app на физический iPhone.
- Проверить запуск Packet Tunnel.
- Проверить, что proxy слушает `127.0.0.1:1443`.
- Проверить Telegram deeplink и подключение к proxy.
- Проверить raw secret `dd...`.
- Проверить Fake TLS secret `ee...`.
- Проверить Cloudflare fallback на сети с блокировкой Telegram.
- Проверить поведение при Wi-Fi/LTE переключении.
- Проверить фоновую живучесть после блокировки экрана.

### Phase 4: Observability and UX

Статус: next best work without deeper device testing.

- Показать в UI текущий route: `direct`, `cloudflare`, `tcp`.
- Показать счетчики upload/download.
- Показать число активных connections.
- Добавить structured logs из extension в App Group.
- Добавить экран диагностики.
- Добавить кнопку "Reset connections".
- Добавить экспорт диагностического bundle для bug reports.

### Phase 5: iOS automation

Статус: planned.

- Добавить App Intents.
- Добавить Shortcuts actions:
  - start tunnel;
  - stop tunnel;
  - regenerate secret;
  - copy Telegram proxy link.
- Рассмотреть widget/Live Activity, если это не конфликтует с ограничениями iOS.

### Phase 6: Transparent tunnel experiment

Статус: optional research.

- Проверить маршрутизацию Telegram DC subnets через Packet Tunnel.
- Оценить, можно ли уйти от ручного `tg://proxy` подключения.
- Сравнить надежность loopback proxy и routed transparent tunnel.
- Не делать это основным путем, пока loopback proxy не проверен на устройстве.

## Ограничения

- Без paid Apple Developer account нельзя проверить главный сценарий на iPhone.
- Симуляторная сборка не доказывает, что Network Extension entitlement работает на устройстве.
- App Store review может отклонять приложения для обхода блокировок.
- Direct pinned-IP WebSocket transport через Network.framework требует field validation, потому что `/apiws`
  resource path в этом режиме ограничен публичным API.
- Cloudflare transport сейчас является самым практичным кандидатом для первой рабочей проверки.

## Распространение

Вероятные каналы распространения:

- TestFlight;
- AltStore;
- SideStore;
- TrollStore;
- локальная установка через Xcode.

App Store как основной канал маловероятен из-за назначения приложения и региональных политик.

## Credits

Протокол и основная логика портированы из
[`xVerdy1337/tg-proxy-android`](https://github.com/xVerdy1337/tg-proxy-android).

Android-проект опирается на идеи и протоколы из:

- Flowseal/tg-ws-proxy;
- TelegramMessenger/MTProxy.

## License

MIT. См. `LICENSE`.
