# Карта порта Android → iOS

Таблица соответствия исходников `tg-proxy-android` и Swift-файлов этого репо.

| Android (Kotlin) | iOS (Swift) | Статус |
|---|---|---|
| `proxy/MtProtoHandshake.kt` (constants) | `JevioCore/MtProtoConstants.swift` | ✅ порт, тесты |
| `proxy/MtProtoHandshake.kt` | `JevioCore/MtProtoHandshake.swift` | ✅ порт, тесты |
| `proxy/FakeTls.kt` | `JevioCore/FakeTls.swift` | ✅ порт, тесты |
| `proxy/MsgSplitter.kt` | `JevioCore/MsgSplitter.swift` | ✅ порт, тесты |
| `javax.crypto Cipher("AES/CTR")` | `JevioCore/AesCtr.swift` (CommonCrypto kCCModeCTR) | ✅ порт, тест |
| `proxy/WebSocketBridge.kt` (OkHttp) | `JevioCore/WebSocketBridge.swift` (Network.framework) | ⚠️ нужна сборка/проверка |
| `proxy/MtProtoProxyServer.kt` (ServerSocket) | `JevioCore/MtProtoProxyServer.swift` + `ClientConnection.swift` (NWListener) | ⚠️ нужна сборка/проверка |
| `service/ProxyService.kt` (foreground service) | `PacketTunnel/PacketTunnelProvider.swift` | ⚠️ нужна сборка/проверка на устройстве |
| `service/ProxyTileService.kt` (Quick Settings) | — (виджет/Shortcuts) | ⬜ TODO |
| `ui/MainScreen.kt` + `ProxyViewModel.kt` (Compose) | `JevioUnlocker/ContentView.swift` + `TunnelController.swift` | ✅ базовый UI |

## Ключевые отличия и места для внимания при сборке

### AES-CTR (критично)
В Android используется `Cipher("AES/CTR/NoPadding")` в режиме ENCRYPT как потоковый XOR — состояние
счётчика сохраняется между `update()`. В Swift это `CCCryptorCreateWithMode(kCCModeCTR, …,
kCCModeOptionCTR_BE)` с одним долгоживущим `CCCryptorRef`. **Проверь big-endian счётчик** —
`kCCModeOptionCTR_BE` это требует. Юнит-тест `testAesCtrStreamingState` сверяет round-trip.

### WebSocket: pin IP + SNI
OkHttp пинил DC-IP через DNS-override, сохраняя TLS SNI = домен. iOS-эквивалент для direct-кандидатов:
`NWEndpoint.hostPort(<IP>, 443)` + `sec_protocol_options_set_tls_server_name(opts, host)`.
Для Cloudflare-кандидатов используется `URLSessionWebSocketTask`, потому что там URL задаётся целиком
и `/apiws` гарантированно попадает в handshake. Direct pinned-IP через Network.framework всё ещё нужно
проверить на Mac/iPhone: если Network.framework не позволит явно задать resource path, direct может
остаться вторичным транспортом, а Cloudflare — основным рабочим путём первой итерации.

### Packet Tunnel: маршрутизация (Фаза 3)
Сейчас `PacketTunnelProvider` ставит минимальные `NEPacketTunnelNetworkSettings` — только чтобы
держать процесс живым; прокси слушает loopback, который доступен другим приложениям без маршрутов.
Варианты на проверку:
- **loopback-only** (как сейчас): простее, но iOS может потребовать хоть какой-то маршрут в туннеле.
- **route Telegram DC subnets** в туннель (тогда даже без `tg://proxy` трафик можно перехватывать —
  это путь к «Архитектуре B», прозрачному туннелю).

### Не портировано (TODO первой итерации)
- `tcpFallback` (прямой TCP к DC :443) — заглушка в `MtProtoProxyServer.handleClient`.
- `maskingRelay` (релей неудачного Fake-TLS пробинга к настоящему домену) — заглушка.
- `resetConnections` на смену сети (Wi-Fi ↔ LTE) — добавить через `NWPathMonitor`.
- routeCache (кэш рабочего эндпоинта) — добавить после того, как гонка заработает.
- Quick Settings-аналог: виджет/App Intents/Shortcuts.
