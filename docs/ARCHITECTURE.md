# Архитектура

## Обзор

Jevio Unlocker — это локальный MTProto-прокси для iOS, упакованный в Network Extension.
Логика обхода идентична Android-версии; меняется только механизм фоновой живучести.

```
┌─────────────┐    tg://proxy     ┌──────────────────────────────┐
│  Telegram   │ ────────────────▶ │  127.0.0.1:1443 (loopback)    │
│   (iOS)     │ ◀──────────────── │  MtProtoProxyServer           │
└─────────────┘   MTProto/obfs2   │  (внутри PacketTunnel ext)    │
                                   └──────────────┬───────────────┘
                                                  │ WebSocket/TLS (/apiws)
                                                  │ + Fake TLS + Cloudflare fallback
                                                  ▼
                                   ┌──────────────────────────────┐
                                   │      Telegram DC (kwsN)        │
                                   └──────────────────────────────┘
```

## Процессы и таргеты

- **JevioUnlocker (app):** SwiftUI UI. Управляет туннелем через `NETunnelProviderManager`
  (`TunnelController`), хранит настройки в App Group, открывает `tg://proxy` deeplink.
- **PacketTunnel (extension):** `NEPacketTunnelProvider`. При старте читает конфиг из
  `providerConfiguration`, поднимает `MtProtoProxyServer` на loopback и держит процесс живым.
- **JevioCore (framework):** общий движок, линкуется в оба таргета.

Общение app ↔ extension: настройки через `UserDefaults(suiteName: group.com.jevio.unlocker)`;
команды старт/стоп — через `NETunnelProviderManager`.

## Поток одного клиента (`MtProtoProxyServer.handleClient`)

1. Принять loopback-соединение от Telegram (`NWListener` → `ClientConnection`).
2. Прочитать первый байт: `0x16` при включённом Fake TLS → путь Fake TLS, иначе сырой obfs2.
3. **Fake TLS:** проверить ClientHello (HMAC по секрету), отдать ServerHello, дальше читать
   внутренний поток через `FakeTlsDeframer`, исходящий — оборачивать в `wrapTlsRecord`.
4. `tryHandshake` → DC, media-флаг, proto-tag, ключи клиента.
5. `generateRelayInit` → обфускация-заголовок для Telegram; `buildCryptoContext` → 4 AES-CTR
   потока (клиент↔, telegram↔).
6. `connectAnyWs` — гонка кандидатов (direct DC web-front с pinned IP + Cloudflare-домены);
   первый открывшийся WS побеждает.
7. Первым WS-фреймом отдаём `relayInit`, дальше `bridgeData`: два насоса с перешифровкой
   client↔telegram, исходящий поток к Telegram нарезается `MsgSplitter` на MTProto-пакеты.

## Фазы развития

- **Фаза 0 (готово):** скелет репо, ядро + тесты, UI, extension, CI.
- **Фаза 1 (в работе):** валидация протокола на ПК (десктоп Telegram → локальный прокси), подбор транспортов.
  Cloudflare `/apiws` переведён на `URLSessionWebSocketTask`; direct pinned-IP/SNI через Network.framework
  остаётся на проверку. Добавлены routeCache, TCP fallback к DC `:443` и masking relay.
- **Фаза 2:** сборка на Mac, прогон `JevioCoreTests`, фикс компиляции сетевого слоя.
- **Фаза 3 (нужен платный Apple Dev):** запуск туннеля на iPhone, настройка
  `NEPacketTunnelNetworkSettings`, фоновая живучесть, реконнект на смене сети (`NWPathMonitor`).
- **Фаза 4:** виджет/Shortcuts, улучшение авто-реконнекта.
- **Фаза 5 (опц.):** «Архитектура B» — прозрачный туннель (route DC subnets), без `tg://proxy`.

См. `PORT_MAP.md` для построчного соответствия с Android и списка открытых вопросов.
