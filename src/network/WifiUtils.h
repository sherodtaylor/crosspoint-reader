#pragma once

namespace WifiUtils {

// Shared WiFi disconnect sequence. Tears down WireGuard (if active),
// stops SNTP, disconnects WiFi, powers off radio.
void disconnectAndOff();

// Same but for AP mode.
void disconnectApAndOff();

}  // namespace WifiUtils
