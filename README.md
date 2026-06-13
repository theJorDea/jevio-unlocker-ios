# Jevio Unlocker — iOS 🛡️

iOS-порт [`tg-proxy-android`](https://github.com/xVerdy1337/tg-proxy-android) (Jevio Unblocker).
Обход блокировки Telegram: приложение поднимает **локальный MTProto-прокси** прямо на iPhone и
туннелирует трафик к серверам Telegram через зашифрованный **WebSocket (TLS)** — с Fake TLS
маскировкой и Cloudflare-fallback. Без сторонних серверов: весь движок крутится на устройстве.

```
Telegram (iOS) → tg://proxy → 127.0.0.1:1443 (loopback)
        ↑ слушает Packet Tunnel Extension (держит процесс живым в фоне)
        → MTProto-релей → WebSocket/TLS (/apiws) → Telegram DC  (+ Cloudflare fallback)
```

> ⚠️ **Статус: первая итерация скелета.** Протокольное ядро (handshake / Fake TLS / msg-splitter)
> портировано из Android 1:1 и покрыто юнит-тестами. Сетевой слой (Network.framework WebSocket,
> loopback-listener, Packet Tunnel) написан, но **требует сборки и полевой проверки на Mac/iPhone** —
> в окружении, где он писался, нет Swift-тулчейна. Ожидается итерация. См. `docs/PORT_MAP.md`.

## Почему Network Extension, а не «фоновый сервис»

iOS не даёт обычному приложению держать в фоне TCP-сервер для другого приложения. Единственный
системный способ — фреймворк **Network Extension**. Здесь `NEPacketTunnelProvider` выступает
«контейнером живучести»: он держит процесс расширения резидентным, а внутри работает
`MtProtoProxyServer` на `127.0.0.1`. Telegram (нативная поддержка MTProto-прокси + deeplink
`tg://proxy`) цепляется к loopback — ровно как «foreground-сервис» на Android.

## Структура

| Папка | Что |
|---|---|
| `Sources/JevioCore` | общий протокол/крипто-движок (порт из Android), линкуется в app и extension |
| `Sources/JevioUnlocker` | SwiftUI-приложение (тумблер, статус, маскировка, секрет, deeplink) |
| `Sources/PacketTunnel` | Network Extension (`NEPacketTunnelProvider`), хостит локальный прокси |
| `Tests/JevioCoreTests` | юнит-тесты ядра (портированы из android `app/src/test`) |
| `docs/` | архитектура и карта порта android→iOS |

## Сборка (на Mac)

Проект описан через [XcodeGen](https://github.com/yonaskolb/XcodeGen) — `.xcodeproj` не коммитится,
генерируется из `project.yml`:

```bash
brew install xcodegen
xcodegen generate
open JevioUnlocker.xcodeproj
```

1. В `project.yml` пропиши свой `DEVELOPMENT_TEAM` (Team ID из Apple Developer).
2. App Group `group.com.jevio.unlocker` и capability **Network Extensions** включи в обоих таргетах.
3. Юнит-тесты ядра гоняются в симуляторе без подписи: схема `JevioUnlocker` → тест `JevioCoreTests`.

CI включён в `.github/workflows/build.yml`: workflow генерирует Xcode-проект, гоняет
`JevioCoreTests` на iOS Simulator и собирает приложение без code signing.

## ⚠️ Что нужно для теста на реальном айфоне

1. **Mac с Xcode** — обязательно для сборки iOS + Network Extension.
2. **Платный Apple Developer ($99/год)** — entitlement `com.apple.developer.networking.networkextension`
   **недоступен на бесплатном Apple ID**. Без него туннель на устройстве не запустится.

Подбор/проверку самого протокола можно делать на ПК (десктоп Telegram → локальный прокси) ещё до оплаты.

## Раздача

App Store режет приложения обхода блокировок (особенно гео РФ), поэтому основной канал —
**сайдлоад** (AltStore / SideStore / TrollStore) или **TestFlight**, как у Android-версии.

## Благодарности

Протокол портирован из `tg-proxy-android` (Jevio Unblocker), который основан на
[Flowseal/tg-ws-proxy](https://github.com/Flowseal) и `TelegramMessenger/MTProxy`.

## Лицензия

MIT
