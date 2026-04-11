#pragma once

#include "activities/Activity.h"
#include "util/ButtonNavigator.h"

/**
 * Submenu for WireGuard VPN settings.
 * Shows enable toggle, endpoint, private key, peer public key, tunnel IP, and PSK.
 */
class WireGuardSettingsActivity final : public Activity {
 public:
  explicit WireGuardSettingsActivity(GfxRenderer& renderer, MappedInputManager& mappedInput)
      : Activity("WireGuardSettings", renderer, mappedInput) {}

  void onEnter() override;
  void onExit() override;
  void loop() override;
  void render(RenderLock&&) override;

 private:
  ButtonNavigator buttonNavigator;

  size_t selectedIndex = 0;
  void handleSelection();
  bool parseConfFile(const char* path);
  void importConfFile();
};
