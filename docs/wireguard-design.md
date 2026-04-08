# WireGuard VPN Integration — Design Document

## Overview

This document describes the architecture for adding transparent WireGuard VPN
support to CrossPoint Reader firmware running on ESP32-C3 (RV32IMC, 380KB RAM,
no PSRAM).

**Goal**: All outbound HTTP(S), SNTP, and OPDS traffic is transparently routed
through a WireGuard tunnel when configured — without modifying any existing
network client code.

## Platform Constraints

- **MCU**: ESP32-C3 — single-core RISC-V @ 160MHz
- **RAM**: ~380KB SRAM, no PSRAM
- **Crypto HW**: AES + SHA acceleration only (not used by WireGuard)
- **WireGuard algorithms**: ChaCha20-Poly1305, BLAKE2s, X25519 — all software
- **ISA**: RV32IMC — no vector, no bitmanip, no crypto extensions, no NEON
- **Alignment**: Faults on unaligned multi-byte loads — crypto code must use
  `memcpy` or byte-wise access for all buffer-to-integer conversions

## Architecture

### Transparent Routing via lwIP netif

```
  Application (UNCHANGED)
  HttpDownloader, OtaUpdater, KOReaderSync, OPDS, SNTP
  ↓ standard socket calls ↓
  ┌──────────────────────────────────────────────────┐
  │ lwIP TCP/IP stack                                 │
  │                                                   │
  │  Routing:                                         │
  │   WG disabled → default route via sta_netif       │
  │   WG enabled  → default route via wg_netif        │
  │                 WG endpoint IP → sta_netif bypass  │
  ├──────────────────────────────────────────────────┤
  │ wg_netif (virtual)     │  sta_netif (WiFi HW)    │
  │  encrypt → WG packet   │  carries encrypted UDP   │
  │  udp_sendto(sta) ──────→                          │
  └──────────────────────────────────────────────────┘
```

All 12 outbound connection points in the firmware (HTTPClient, esp_http_client,
SNTP, mDNS, UDP discovery) route through lwIP. Changing the default route to
the WireGuard netif makes the tunnel transparent to application code.

### Based on wireguard-lwip (smartalock)

Both major ESP32 WireGuard projects (microlink by CamM2325, tailscale-iot by
alfs) vendor the same upstream: `smartalock/wireguard-lwip`. This is a:

- Malloc-free C implementation
- Designed for lwIP integration
- BSD 3-Clause licensed
- ~80KB source (after stripping ARM assembly and unused X25519)

We vendor it directly, stripping unnecessary code:

| Removed | Reason | Savings |
|---------|--------|---------|
| `crypto/cortex/*` | ARM Cortex-M0 assembly — wrong arch (RISC-V) | 66KB source |
| `crypto/refc/x25519.c/h` | Replace with mbedtls Curve25519 (already linked) | 16KB source |

### Optimizations from Reference Projects

**From microlink (CamM2325):**
- Zero-copy receive: decrypt in-place in pbuf, strip WG header, feed to
  `ip_input()` without allocating a second pbuf
- `wireguard-platform-esp32.c`: ESP32 platform functions already implemented
  and tested (esp_fill_random, sys_now, gettimeofday TAI64N)

**From tailscale-iot (alfs):**
- Watchdog feeding around crypto operations — X25519 DH can block 100-300ms
  on single-core RISC-V, triggering WDT reset without `esp_task_wdt_reset()`
- Known wireguard-lwip bugs documented with workarounds:
  - sender_index=0 (invalid) on handshake initiation
  - Responder keypair stored in `next_keypair` instead of `curr_keypair`

## File Layout

```
lib/WireGuard/
├── wireguard.c              ← FROM wireguard-lwip (core protocol, unmodified)
├── wireguard.h              ← FROM wireguard-lwip (structs, constants)
├── wireguardif.c            ← FROM wireguard-lwip (patched: zero-copy recv, WDT feed)
├── wireguardif.h            ← FROM wireguard-lwip (netif API)
├── wireguard-platform.c     ← FROM microlink (ESP32 platform: RNG, time, TAI64N)
├── wireguard-platform.h     ← FROM wireguard-lwip (MAX_PEERS=1, MAX_SRC_IPS=1)
├── crypto.h                 ← MODIFIED: swap x25519 define → mbedtls ECDH
├── crypto.c                 ← FROM wireguard-lwip (zero/compare utils)
├── crypto/
│   └── refc/
│       ├── blake2s.c/h              ← FROM wireguard-lwip (RFC 7693)
│       ├── chacha20.c/h             ← FROM wireguard-lwip (cr.yp.to ref)
│       ├── chacha20poly1305.c/h     ← FROM wireguard-lwip (RFC 7539)
│       └── poly1305-donna*          ← FROM wireguard-lwip (donna-32)
├── WireGuardManager.h/cpp   ← NEW: CrossPoint singleton lifecycle
└── library.json             ← PlatformIO library manifest
```

## Required Patches to Vendored Code

### 1. Packed Struct Alignment (RISC-V Safety)

All WireGuard message structs in `wireguard.h` use `__attribute__((packed))` and
are cast from pbuf payloads. On ESP32-C3 RISC-V, direct multi-byte member access
on unaligned addresses **will fault**. The counter/nonce fields already use
byte-level macros (`U8TO64_LITTLE`), but all struct member access from pbuf
pointers must be audited. Patch: access packed struct fields via `memcpy`.

### 2. Strip Responder-Only Code (~350 lines)

Remove functions only needed for WireGuard servers/responders:
- `wireguard_process_initiation_message()` — processes incoming Type 1
- `wireguard_create_handshake_response()` — creates Type 2
- `wireguard_create_cookie_reply()` — creates Type 3
- `wireguard_check_mac1/mac2()` — validates incoming initiation MACs
- `generate_cookie_secret/peer_cookie()` — DoS cookie generation
- `wireguardif_send_handshake_response/cookie()` — sends Type 2/3
- `wireguardif_check_initiation_message()` — incoming initiation validation
- `xchacha20poly1305_encrypt()` — only used for cookie reply creation
- Type 1 (initiation) handler in `wireguardif_network_rx()`

Keep `xchacha20poly1305_decrypt()` — server may send cookie replies (Type 3).

### 3. Zero-Copy Receive (from microlink pattern)

Patch `wireguardif_process_data_message()` to decrypt in-place in the received
pbuf and strip the WG header, instead of allocating a second pbuf. Feed
decrypted data directly to `ip_input()`.

### 4. Watchdog Feeding (from tailscale-iot pattern)

Add `esp_task_wdt_reset()` before and after X25519 DH operations in
`wireguard_create_handshake_initiation()` and
`wireguard_process_handshake_response()`. X25519 can block 100-300ms on
single-core 160MHz RISC-V, triggering WDT reset without this.

### 5. Device Struct Savings (-68 bytes)

Remove responder-only fields from `wireguard_device`:
- `cookie_secret[32]` — DoS cookie secret
- `cookie_secret_millis` — cookie rotation timer
- `label_cookie_key[32]` — device-level cookie MAC key

## Integration Points

### WiFi Lifecycle — 2 Hook Points

**Post-connect** (`WifiSelectionActivity::onComplete`, line 691):
```cpp
if (connected) {
    WireGuardManager::getInstance().onWifiConnected();
}
```

**Pre-disconnect** (6 existing sites → refactored to shared helper):
```cpp
// src/network/WifiUtils.h
namespace WifiUtils {
inline void disconnectAndOff() {
    WireGuardManager::getInstance().onWifiDisconnecting();
    if (esp_sntp_enabled()) esp_sntp_stop();
    WiFi.disconnect(false);
    delay(100);
    WiFi.mode(WIFI_OFF);
    delay(100);
}
}
```

Replaces duplicated disconnect code in:
- KOReaderAuthActivity.cpp:69-72
- OtaUpdateActivity.cpp:70-73
- KOReaderSyncActivity.cpp:43-50
- CalibreConnectActivity.cpp:58-61
- CrossPointWebServerActivity.cpp:91-97
- OpdsBookBrowserActivity.cpp:43, 385-386

### WireGuardManager Lifecycle

```
onWifiConnected():
  1. Check SETTINGS.wireguardEnabled — if 0, return (no-op)
  2. Sync NTP (esp_sntp, same pattern as KOReaderSyncActivity:17-41)
  3. Create wireguard_device with private key from SETTINGS
  4. Add peer with public key, endpoint, allowed IPs
  5. Register wg_netif with lwIP (netif_add)
  6. Set wg_netif as default gateway
  7. Add host route for WG endpoint IP → sta_netif (bypass tunnel)
  8. Initiate handshake (wireguardif_connect)

onWifiDisconnecting():
  1. Restore default route to sta_netif
  2. Remove wg_netif from lwIP
  3. Clean up wireguard_device
```

### Settings

Added to `CrossPointSettings.h`:
```cpp
uint8_t wireguardEnabled = 0;
char wireguardEndpoint[64] = "";         // "1.2.3.4:51820"
char wireguardPrivateKey[45] = "";       // Base64 Curve25519 key
char wireguardPeerPublicKey[45] = "";    // Base64 Curve25519 key
char wireguardTunnelIP[16] = "";         // "10.0.0.2"
char wireguardPeerAllowedIPs[20] = "0.0.0.0/0";
```

~210 bytes added to settings struct. Persisted via existing NVS infrastructure.

## Memory Budget

| Component | Flash (.text) | RAM (static) | RAM (runtime) |
|-----------|--------------|-------------|---------------|
| wireguard.c (protocol) | ~15KB | 0 | stack only |
| wireguardif.c (netif) | ~12KB | ~200B | netif + UDP PCB |
| blake2s | ~2KB | 0 | 0 |
| chacha20 + poly1305 | ~6KB | 0 | 0 |
| chacha20poly1305 AEAD | ~4KB | 0 | 0 |
| platform + crypto.c | ~1KB | 0 | 0 |
| WireGuardManager | ~1KB | ~8B | 0 |
| device + peer structs | 0 | ~1000B | 0 |
| **Total** | **~41KB** | **~1.2KB** | **~200B** |

No task stack increases required. Handshake runs in the calling task context
with watchdog feeding around X25519 DH operations.

## Implementation Phases

### Phase 1: Vendor and strip wireguard-lwip
- Copy core files, delete cortex/ ASM and x25519 reference
- Modify crypto.h to redirect X25519 to mbedtls
- Write wireguard-platform.c for ESP32-C3
- Verify: `pio run` compiles cleanly

### Phase 2: WireGuardManager + netif integration
- Implement singleton with onWifiConnected/onWifiDisconnecting
- Create lwIP netif, set routing
- NTP sync before handshake
- Verify: handshake completes against Linux `wg-quick` peer

### Phase 3: CrossPoint integration
- Add settings fields to CrossPointSettings
- Create WireGuardSettingsActivity (key entry, enable/disable)
- Hook WifiSelectionActivity::onComplete
- Create WifiUtils.h, refactor 6 disconnect sites
- Verify: OPDS download, OTA check, KOReader sync all work through tunnel

### Phase 4: Hardening
- Heap monitoring (ESP.getFreeHeap() before/after tunnel)
- Test all 4 orientations with tunnel active
- Test tunnel teardown/reconnect cycle
- Watchdog timing validation on ESP32-C3

## Security Considerations

- Private keys stored in NVS (same security model as WiFi passwords)
- No certificate pinning needed (WireGuard uses static public keys)
- Crypto primitives from auditable reference sources (RFC 7693, poly1305-donna,
  cr.yp.to ChaCha20)
- `crypto_zero()` wipes key material on teardown
- Replay protection via sliding window bitmap (built into wireguard-lwip)

## References

- [wireguard-lwip](https://github.com/smartalock/wireguard-lwip) — upstream
- [microlink](https://github.com/CamM2325/microlink) — production ESP32 reference
- [tailscale-iot](https://github.com/alfs/tailscale-iot) — ESP32-C3 reference + bug docs
- [WireGuard whitepaper](https://www.wireguard.com/papers/wireguard.pdf)
- [Noise Protocol Framework](https://noiseprotocol.org/noise.html)
