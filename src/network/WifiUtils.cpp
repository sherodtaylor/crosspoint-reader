#include "WifiUtils.h"

#include <WiFi.h>
#include <esp_sntp.h>

namespace WifiUtils {

void disconnectAndOff() {
  if (esp_sntp_enabled()) {
    esp_sntp_stop();
  }
  WiFi.disconnect(false);
  delay(100);
  WiFi.mode(WIFI_OFF);
  delay(100);
}

void disconnectApAndOff() {
  if (esp_sntp_enabled()) {
    esp_sntp_stop();
  }
  WiFi.softAPdisconnect(true);
  delay(30);
  WiFi.mode(WIFI_OFF);
  delay(30);
}

}  // namespace WifiUtils
