#include "WireGuardCredentialStore.h"

#include <HalStorage.h>
#include <Logging.h>

#include "../JsonSettingsIO.h"

// Initialize the static instance
WireGuardCredentialStore WireGuardCredentialStore::instance;

namespace {
constexpr char WG_FILE_JSON[] = "/.crosspoint/wireguard.json";
}  // namespace

bool WireGuardCredentialStore::saveToFile() const {
  Storage.mkdir("/.crosspoint");
  return JsonSettingsIO::saveWireGuard(*this, WG_FILE_JSON);
}

bool WireGuardCredentialStore::loadFromFile() {
  if (!Storage.exists(WG_FILE_JSON)) {
    LOG_DBG("WGS", "No credentials file found");
    return false;
  }

  String json = Storage.readFile(WG_FILE_JSON);
  if (json.isEmpty()) {
    LOG_ERR("WGS", "Failed to read credentials file");
    return false;
  }

  bool resave = false;
  bool result = JsonSettingsIO::loadWireGuard(*this, json.c_str(), &resave);
  if (result && resave) {
    saveToFile();
    LOG_DBG("WGS", "Resaved WireGuard credentials to update format");
  }
  return result;
}
