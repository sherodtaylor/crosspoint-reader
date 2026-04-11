#include "WireGuardManager.h"

#include <Logging.h>
#include <WiFi.h>
#include <esp_sntp.h>
#include <lwip/netif.h>
#include <cstring>

#include "CrossPointSettings.h"
#include "CrossPointState.h"
#include "WireGuardCredentialStore.h"

extern "C" {
#include "wireguard.h"
#include "wireguardif.h"
}

WireGuardManager WireGuardManager::instance;

WireGuardManager& WireGuardManager::getInstance() { return instance; }

// ---------------------------------------------------------------------------
// NTP synchronisation — WireGuard TAI64N timestamps require wall-clock time
// ---------------------------------------------------------------------------
bool WireGuardManager::syncNTP() {
  esp_sntp_setoperatingmode(ESP_SNTP_OPMODE_POLL);
  esp_sntp_setservername(0, "pool.ntp.org");
  esp_sntp_init();

  static constexpr int kMaxAttempts = 50;  // 50 * 100 ms = 5 s
  for (int i = 0; i < kMaxAttempts; ++i) {
    if (cancelRequested) {
      LOG_DBG("WG", "NTP sync cancelled");
      esp_sntp_stop();
      return false;
    }
    if (sntp_get_sync_status() == SNTP_SYNC_STATUS_COMPLETED) {
      LOG_DBG("WG", "NTP sync complete");
      return true;
    }
    vTaskDelay(pdMS_TO_TICKS(100));
  }

  LOG_ERR("WG", "NTP sync timed out after 5 s");
  esp_sntp_stop();
  return false;
}

// ---------------------------------------------------------------------------
// Tunnel bring-up
// ---------------------------------------------------------------------------
bool WireGuardManager::initTunnel() {
  // --- Decode private key ---
  uint8_t privateKey[WIREGUARD_PRIVATE_KEY_LEN];
  size_t privateKeyLen = sizeof(privateKey);
  if (!wireguard_base64_decode(WG_STORE.getPrivateKey().c_str(), privateKey,
                               &privateKeyLen) ||
      privateKeyLen != WIREGUARD_PRIVATE_KEY_LEN) {
    LOG_ERR("WG", "Failed to decode private key");
    return false;
  }

  // --- Decode peer public key ---
  uint8_t peerPublicKey[WIREGUARD_PUBLIC_KEY_LEN];
  size_t peerPubKeyLen = sizeof(peerPublicKey);
  if (!wireguard_base64_decode(WG_STORE.getPeerPublicKey().c_str(), peerPublicKey,
                               &peerPubKeyLen) ||
      peerPubKeyLen != WIREGUARD_PUBLIC_KEY_LEN) {
    LOG_ERR("WG", "Failed to decode peer public key");
    return false;
  }

  // --- Decode optional preshared key ---
  uint8_t psk[WIREGUARD_SESSION_KEY_LEN];
  bool hasPsk = false;
  if (!WG_STORE.getPresharedKey().empty()) {
    size_t pskLen = sizeof(psk);
    if (!wireguard_base64_decode(WG_STORE.getPresharedKey().c_str(), psk,
                                 &pskLen) ||
        pskLen != WIREGUARD_SESSION_KEY_LEN) {
      LOG_ERR("WG", "Failed to decode preshared key");
      return false;
    }
    hasPsk = true;
  }

  // --- Parse endpoint "host:port" ---
  char endpointBuf[64];
  strncpy(endpointBuf, WG_STORE.getEndpoint().c_str(), sizeof(endpointBuf) - 1);
  endpointBuf[sizeof(endpointBuf) - 1] = '\0';

  const char* colonPos = strrchr(endpointBuf, ':');
  if (!colonPos) {
    LOG_ERR("WG", "Endpoint missing ':port' — got \"%s\"", endpointBuf);
    return false;
  }
  endpointBuf[colonPos - endpointBuf] = '\0';
  const char* hostStr = endpointBuf;
  uint16_t endpointPort =
      static_cast<uint16_t>(strtoul(colonPos + 1, nullptr, 10));
  if (endpointPort == 0) {
    LOG_ERR("WG", "Invalid endpoint port");
    return false;
  }

  // --- Resolve endpoint IP (numeric only, no DNS) ---
  ip_addr_t endpointIp;
  memset(&endpointIp, 0, sizeof(endpointIp));
  if (!ipaddr_aton(hostStr, &endpointIp)) {
    LOG_ERR("WG", "Cannot parse endpoint IP \"%s\" (DNS not supported)",
            hostStr);
    return false;
  }

  // --- Parse tunnel IP ---
  ip_addr_t tunnelIp;
  memset(&tunnelIp, 0, sizeof(tunnelIp));
  if (!ipaddr_aton(WG_STORE.getTunnelIP().c_str(), &tunnelIp)) {
    LOG_ERR("WG", "Cannot parse tunnel IP \"%s\"", WG_STORE.getTunnelIP().c_str());
    return false;
  }

  // --- Prepare netif init data ---
  struct wireguardif_init_data initData;
  memset(&initData, 0, sizeof(initData));
  initData.private_key = WG_STORE.getPrivateKey().c_str();
  initData.listen_port = WIREGUARDIF_DEFAULT_PORT;
  initData.bind_netif = nullptr;

  ip_addr_t netmask;
  ip_addr_t gateway;
  IP_ADDR4(&netmask, 255, 255, 255, 0);
  ip_addr_set_zero(&gateway);

  // --- Allocate netif on heap (sizeof(struct netif) too large for stack) ---
  auto* wgNetifHeap = static_cast<struct netif*>(malloc(sizeof(struct netif)));
  if (!wgNetifHeap) {
    LOG_ERR("WG", "malloc failed: netif (%u bytes)", static_cast<unsigned>(sizeof(struct netif)));
    return false;
  }
  memset(wgNetifHeap, 0, sizeof(struct netif));

  // --- Add the WireGuard netif ---
  struct netif* nif =
      netif_add(wgNetifHeap, ip_2_ip4(&tunnelIp), ip_2_ip4(&netmask),
                ip_2_ip4(&gateway), &initData, &wireguardif_init, &ip_input);
  if (!nif) {
    LOG_ERR("WG", "netif_add failed");
    free(wgNetifHeap);
    return false;
  }
  wgNetif = nif;
  netif_set_up(wgNetif);

  // --- Configure and add the peer ---
  struct wireguardif_peer peer;
  wireguardif_peer_init(&peer);
  peer.public_key = WG_STORE.getPeerPublicKey().c_str();
  peer.preshared_key = hasPsk ? psk : nullptr;
  peer.endpoint_ip = endpointIp;
  peer.endport_port = endpointPort;
  peer.keep_alive = 25;

  IP_ADDR4(&peer.allowed_ip, 0, 0, 0, 0);
  IP_ADDR4(&peer.allowed_mask, 0, 0, 0, 0);

  uint8_t idx = WIREGUARDIF_INVALID_INDEX;
  err_t err = wireguardif_add_peer(wgNetif, &peer, &idx);
  if (err != ERR_OK || idx == WIREGUARDIF_INVALID_INDEX) {
    LOG_ERR("WG", "wireguardif_add_peer failed: %d", static_cast<int>(err));
    netif_remove(wgNetif);
    free(wgNetif);
    wgNetif = nullptr;
    return false;
  }
  peerIndex = idx;

  // --- Initiate handshake ---
  err = wireguardif_connect(wgNetif, peerIndex);
  if (err != ERR_OK) {
    LOG_ERR("WG", "wireguardif_connect failed: %d", static_cast<int>(err));
    netif_remove(wgNetif);
    free(wgNetif);
    wgNetif = nullptr;
    return false;
  }

  // --- Wait for handshake completion (up to 10 s, cancellable) ---
  static constexpr int kHandshakeAttempts = 100;  // 100 * 100 ms = 10 s
  for (int i = 0; i < kHandshakeAttempts; ++i) {
    if (cancelRequested) {
      LOG_DBG("WG", "Handshake cancelled");
      wireguardif_disconnect(wgNetif, peerIndex);
      wireguardif_shutdown(wgNetif);
      netif_remove(wgNetif);
      free(wgNetif);
      wgNetif = nullptr;
      return false;
    }
    ip_addr_t currentIp;
    u16_t currentPort;
    if (wireguardif_peer_is_up(wgNetif, peerIndex, &currentIp, &currentPort) ==
        ERR_OK) {
      LOG_DBG("WG", "Tunnel up — peer handshake complete");
      netif_set_default(wgNetif);
      connected = true;
      APP_STATE.vpnConnected = true;
      return true;
    }
    vTaskDelay(pdMS_TO_TICKS(100));
  }

  LOG_ERR("WG", "Handshake timed out after 10 s");
  wireguardif_disconnect(wgNetif, peerIndex);
  wireguardif_shutdown(wgNetif);
  netif_remove(wgNetif);
  free(wgNetif);
  wgNetif = nullptr;
  return false;
}

// ---------------------------------------------------------------------------
// Tunnel teardown
// ---------------------------------------------------------------------------
void WireGuardManager::teardownTunnel() {
  if (!wgNetif) return;

  // Restore WiFi STA as the default route
  for (struct netif* nif = netif_list; nif != nullptr; nif = nif->next) {
    if (nif != wgNetif && nif->name[0] == 'e' && nif->name[1] == 'n') {
      netif_set_default(nif);
      LOG_DBG("WG", "Restored STA netif as default route");
      break;
    }
  }

  wireguardif_disconnect(wgNetif, peerIndex);
  wireguardif_shutdown(wgNetif);
  netif_remove(wgNetif);
  free(wgNetif);
  wgNetif = nullptr;
  connected = false;
  APP_STATE.vpnConnected = false;
  LOG_DBG("WG", "Tunnel torn down");
}

// ---------------------------------------------------------------------------
// Background connect task — runs NTP sync + handshake off the UI thread
// ---------------------------------------------------------------------------
void WireGuardManager::connectTask(void* param) {
  auto& mgr = *static_cast<WireGuardManager*>(param);

  bool success = false;
  if (mgr.syncNTP() && !mgr.cancelRequested) {
    success = mgr.initTunnel();
    if (!success) {
      esp_sntp_stop();
    }
  }

  mgr.connecting = false;
  APP_STATE.vpnConnecting = false;

  // Signal failure to UI (unless cancelled — cancellation is not an error)
  if (!success && !mgr.cancelRequested) {
    APP_STATE.vpnConnectionFailed = true;
  }

  mgr.taskHandle = nullptr;
  vTaskDelete(nullptr);
}

// ---------------------------------------------------------------------------
// Public hooks
// ---------------------------------------------------------------------------
void WireGuardManager::onWifiConnected() {
  if (!SETTINGS.wireguardEnabled) return;

  WG_STORE.loadFromFile();

  if (!WG_STORE.isConfigured()) {
    LOG_ERR("WG", "WireGuard enabled but config incomplete — skipping");
    return;
  }

  // Don't start a second connect if one is already in progress
  if (connecting || connected) return;

  LOG_DBG("WG", "Starting WireGuard tunnel setup (background)");
  cancelRequested = false;
  connecting = true;
  APP_STATE.vpnConnecting = true;
  APP_STATE.vpnConnectionFailed = false;

  // 4096 bytes stack per CLAUDE.md guidelines for network tasks
  xTaskCreate(&connectTask, "wg_connect", 4096, this, 1, &taskHandle);
}

void WireGuardManager::onWifiDisconnecting() {
  // Cancel any in-progress connection attempt
  if (connecting && taskHandle) {
    cancelRequested = true;
    // Wait for the background task to notice and exit (up to 2s)
    for (int i = 0; i < 20 && connecting; ++i) {
      vTaskDelay(pdMS_TO_TICKS(100));
    }
    // If task is still stuck, delete it forcefully
    if (taskHandle) {
      vTaskDelete(taskHandle);
      taskHandle = nullptr;
      connecting = false;
    }
  }

  if (connected) {
    teardownTunnel();
  }
}
