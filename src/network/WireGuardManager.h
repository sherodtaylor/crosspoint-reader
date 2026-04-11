#pragma once

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

#include <cstdint>

struct netif;

class WireGuardManager {
 public:
  static WireGuardManager& getInstance();

  // Called after WiFi STA connects. Spawns a background task to sync NTP
  // and establish the tunnel. Non-blocking — returns immediately.
  void onWifiConnected();

  // Called before WiFi disconnects. Cancels any in-progress connection
  // attempt and tears down the tunnel if active.
  void onWifiDisconnecting();

  bool isConnected() const { return connected; }
  bool isConnecting() const { return connecting; }

 private:
  WireGuardManager() = default;
  ~WireGuardManager() = default;
  WireGuardManager(const WireGuardManager&) = delete;
  WireGuardManager& operator=(const WireGuardManager&) = delete;

  bool syncNTP();
  bool initTunnel();
  void teardownTunnel();

  static void connectTask(void* param);

  struct netif* wgNetif = nullptr;
  TaskHandle_t taskHandle = nullptr;
  uint8_t peerIndex = 0;
  volatile bool connected = false;
  volatile bool connecting = false;
  volatile bool cancelRequested = false;

  static WireGuardManager instance;
};
