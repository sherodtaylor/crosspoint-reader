#include "WireGuardSettingsActivity.h"

#include <GfxRenderer.h>
#include <HalStorage.h>
#include <I18n.h>
#include <Logging.h>

#include <cstring>
#include <ini.h>

#include "CrossPointSettings.h"
#include "CrossPointState.h"
#include "MappedInputManager.h"
#include "activities/util/ConfirmationActivity.h"
#include "activities/util/KeyboardEntryActivity.h"
#include "components/UITheme.h"
#include "fontIds.h"
#include "network/WireGuardCredentialStore.h"
#include "network/WireGuardManager.h"

namespace {
constexpr int MENU_ITEMS = 7;
static constexpr StrId menuNames[MENU_ITEMS] = {StrId::STR_WIREGUARD_ENABLED,    StrId::STR_WIREGUARD_ENDPOINT,
                                     StrId::STR_WIREGUARD_PRIVATE_KEY, StrId::STR_WIREGUARD_PEER_KEY,
                                     StrId::STR_WIREGUARD_TUNNEL_IP,   StrId::STR_WIREGUARD_PSK,
                                     StrId::STR_WIREGUARD_IMPORT_CONF};
}  // namespace

void WireGuardSettingsActivity::onEnter() {
  Activity::onEnter();

  WG_STORE.loadFromFile();
  selectedIndex = 0;
  requestUpdate();
}

void WireGuardSettingsActivity::onExit() { Activity::onExit(); }

void WireGuardSettingsActivity::loop() {
  // Check if a background VPN connection attempt failed — show retry/cancel popup
  if (APP_STATE.vpnConnectionFailed) {
    APP_STATE.vpnConnectionFailed = false;
    startActivityForResult(
        std::make_unique<ConfirmationActivity>(renderer, mappedInput, tr(STR_WIREGUARD),
                                               tr(STR_WIREGUARD_CONNECT_FAILED)),
        [this](const ActivityResult& result) {
          if (!result.isCancelled) {
            // Retry — trigger a new connection attempt
            WireGuardManager::getInstance().onWifiConnected();
          }
          requestUpdate();
        });
    return;
  }

  if (mappedInput.wasPressed(MappedInputManager::Button::Back)) {
    finish();
    return;
  }

  if (mappedInput.wasPressed(MappedInputManager::Button::Confirm)) {
    handleSelection();
    return;
  }

  // Handle navigation
  buttonNavigator.onNext([this] {
    selectedIndex = (selectedIndex + 1) % MENU_ITEMS;
    requestUpdate();
  });

  buttonNavigator.onPrevious([this] {
    selectedIndex = (selectedIndex + MENU_ITEMS - 1) % MENU_ITEMS;
    requestUpdate();
  });
}

void WireGuardSettingsActivity::handleSelection() {
  if (selectedIndex == 0) {
    // Enabled toggle — flip directly
    SETTINGS.wireguardEnabled = !SETTINGS.wireguardEnabled;
    SETTINGS.saveToFile();
    requestUpdate();
  } else if (selectedIndex == 1) {
    // Endpoint
    startActivityForResult(std::make_unique<KeyboardEntryActivity>(renderer, mappedInput, tr(STR_WIREGUARD_ENDPOINT),
                                                                   WG_STORE.getEndpoint().c_str(), 63, false),
                           [this](const ActivityResult& result) {
                             if (!result.isCancelled) {
                               const auto& kb = std::get<KeyboardResult>(result.data);
                               WG_STORE.setEndpoint(kb.text);
                               WG_STORE.saveToFile();
                             }
                           });
  } else if (selectedIndex == 2) {
    // Private Key
    startActivityForResult(std::make_unique<KeyboardEntryActivity>(renderer, mappedInput, tr(STR_WIREGUARD_PRIVATE_KEY),
                                                                   WG_STORE.getPrivateKey().c_str(), 47, false),
                           [this](const ActivityResult& result) {
                             if (!result.isCancelled) {
                               const auto& kb = std::get<KeyboardResult>(result.data);
                               WG_STORE.setPrivateKey(kb.text);
                               WG_STORE.saveToFile();
                             }
                           });
  } else if (selectedIndex == 3) {
    // Peer Public Key
    startActivityForResult(std::make_unique<KeyboardEntryActivity>(renderer, mappedInput, tr(STR_WIREGUARD_PEER_KEY),
                                                                   WG_STORE.getPeerPublicKey().c_str(), 47, false),
                           [this](const ActivityResult& result) {
                             if (!result.isCancelled) {
                               const auto& kb = std::get<KeyboardResult>(result.data);
                               WG_STORE.setPeerPublicKey(kb.text);
                               WG_STORE.saveToFile();
                             }
                           });
  } else if (selectedIndex == 4) {
    // Tunnel IP
    startActivityForResult(std::make_unique<KeyboardEntryActivity>(renderer, mappedInput, tr(STR_WIREGUARD_TUNNEL_IP),
                                                                   WG_STORE.getTunnelIP().c_str(), 15, false),
                           [this](const ActivityResult& result) {
                             if (!result.isCancelled) {
                               const auto& kb = std::get<KeyboardResult>(result.data);
                               WG_STORE.setTunnelIP(kb.text);
                               WG_STORE.saveToFile();
                             }
                           });
  } else if (selectedIndex == 5) {
    // Preshared Key
    startActivityForResult(std::make_unique<KeyboardEntryActivity>(renderer, mappedInput, tr(STR_WIREGUARD_PSK),
                                                                   WG_STORE.getPresharedKey().c_str(), 47, false),
                           [this](const ActivityResult& result) {
                             if (!result.isCancelled) {
                               const auto& kb = std::get<KeyboardResult>(result.data);
                               WG_STORE.setPresharedKey(kb.text);
                               WG_STORE.saveToFile();
                             }
                           });
  } else if (selectedIndex == 6) {
    importConfFile();
  }
}

// inih callback: called for each (section, key, value) in the .conf file
static int wgConfHandler(void* user, const char* section, const char* key, const char* value) {
  auto* found = static_cast<uint8_t*>(user);  // bit 0 = privateKey, bit 1 = publicKey

  if (strcasecmp(section, "Interface") == 0) {
    if (strcasecmp(key, "PrivateKey") == 0) {
      WG_STORE.setPrivateKey(value);
      *found |= 0x01;
      LOG_DBG("WGCONF", "Parsed PrivateKey");
    } else if (strcasecmp(key, "Address") == 0) {
      // Strip CIDR suffix (e.g., "10.0.0.2/24" → "10.0.0.2")
      char addr[16];
      strncpy(addr, value, sizeof(addr) - 1);
      addr[sizeof(addr) - 1] = '\0';
      char* slash = strchr(addr, '/');
      if (slash) *slash = '\0';
      WG_STORE.setTunnelIP(addr);
      LOG_DBG("WGCONF", "Parsed Address: %s", addr);
    }
  } else if (strcasecmp(section, "Peer") == 0) {
    if (strcasecmp(key, "PublicKey") == 0) {
      WG_STORE.setPeerPublicKey(value);
      *found |= 0x02;
      LOG_DBG("WGCONF", "Parsed PublicKey");
    } else if (strcasecmp(key, "PresharedKey") == 0) {
      WG_STORE.setPresharedKey(value);
      LOG_DBG("WGCONF", "Parsed PresharedKey");
    } else if (strcasecmp(key, "Endpoint") == 0) {
      WG_STORE.setEndpoint(value);
      LOG_DBG("WGCONF", "Parsed Endpoint: %s", value);
    }
  }
  return 1;  // 1 = success, 0 = stop parsing
}

bool WireGuardSettingsActivity::parseConfFile(const char* path) {
  // Read file into a heap buffer for ini_parse_string().
  // Stack allocation rejected: typical .conf is 200-400 bytes but buffer must
  // accommodate the full file; 1KB exceeds the 256-byte stack safety limit.
  static constexpr size_t CONF_BUF_SIZE = 1024;
  auto* buf = static_cast<char*>(malloc(CONF_BUF_SIZE));
  if (!buf) {
    LOG_ERR("WGCONF", "malloc failed: %u bytes", static_cast<unsigned>(CONF_BUF_SIZE));
    return false;
  }

  size_t bytesRead = Storage.readFileToBuffer(path, buf, CONF_BUF_SIZE);
  if (bytesRead == 0) {
    LOG_ERR("WGCONF", "Failed to read conf file: %s", path);
    free(buf);
    return false;
  }

  uint8_t found = 0;
  int err = ini_parse_string(buf, wgConfHandler, &found);
  free(buf);

  if (err != 0) {
    LOG_ERR("WGCONF", "Parse error at line %d", err);
    return false;
  }

  if ((found & 0x03) != 0x03) {
    LOG_ERR("WGCONF", "Missing required keys (PrivateKey=%d, PublicKey=%d)", found & 0x01, (found >> 1) & 0x01);
    return false;
  }

  SETTINGS.wireguardEnabled = 1;
  return true;
}

void WireGuardSettingsActivity::importConfFile() {
  // Scan SD card root for .conf files using directory iteration
  HalFile dir = Storage.open("/");
  if (!dir || !dir.isDirectory()) {
    LOG_ERR("WGCONF", "Failed to open SD card root");
    return;
  }

  char confPath[128] = {0};
  char name[128];
  int confCount = 0;

  for (auto file = dir.openNextFile(); file; file = dir.openNextFile()) {
    if (file.isDirectory()) {
      file.close();
      continue;
    }
    file.getName(name, sizeof(name));

    // Check for .conf extension (case-insensitive)
    size_t nameLen = strlen(name);
    if (nameLen > 5 && strcasecmp(name + nameLen - 5, ".conf") == 0) {
      confCount++;
      if (confCount == 1) {
        // Store the first .conf file path
        snprintf(confPath, sizeof(confPath), "/%s", name);
      }
    }
    file.close();
  }
  dir.close();

  if (confCount == 0) {
    LOG_INF("WGCONF", "No .conf files found on SD card root");
    return;
  }

  if (confCount > 1) {
    LOG_INF("WGCONF", "Multiple .conf files found (%d), using first: %s", confCount, confPath);
  }

  LOG_INF("WGCONF", "Importing WireGuard config from: %s", confPath);

  if (parseConfFile(confPath)) {
    WG_STORE.saveToFile();
    SETTINGS.saveToFile();
    LOG_INF("WGCONF", "Config imported successfully from %s", confPath);
    requestUpdate();
  } else {
    LOG_ERR("WGCONF", "Failed to parse config file: %s", confPath);
  }
}

void WireGuardSettingsActivity::render(RenderLock&&) {
  renderer.clearScreen();

  const auto& metrics = UITheme::getInstance().getMetrics();
  const auto pageWidth = renderer.getScreenWidth();
  const auto pageHeight = renderer.getScreenHeight();
  GUI.drawHeader(renderer, Rect{0, metrics.topPadding, pageWidth, metrics.headerHeight}, tr(STR_WIREGUARD));
  GUI.drawSubHeader(renderer, Rect{0, metrics.topPadding + metrics.headerHeight, pageWidth, metrics.tabBarHeight},
                    tr(STR_WIREGUARD_SETTINGS_HINT));

  const int contentTop = metrics.topPadding + metrics.headerHeight + metrics.verticalSpacing + metrics.tabBarHeight;
  const int contentHeight = pageHeight - contentTop - metrics.buttonHintsHeight - metrics.verticalSpacing * 2;
  GUI.drawList(
      renderer, Rect{0, contentTop, pageWidth, contentHeight}, static_cast<int>(MENU_ITEMS),
      static_cast<int>(selectedIndex), [](int index) { return std::string(I18N.get(menuNames[index])); }, nullptr,
      nullptr,
      [this](int index) {
        // Draw status for each setting
        if (index == 0) {
          return std::string(SETTINGS.wireguardEnabled ? tr(STR_STATE_ON) : tr(STR_STATE_OFF));
        } else if (index == 1) {
          return !WG_STORE.getEndpoint().empty() ? WG_STORE.getEndpoint() : std::string(tr(STR_NOT_SET));
        } else if (index == 2) {
          return !WG_STORE.getPrivateKey().empty() ? std::string("******") : std::string(tr(STR_NOT_SET));
        } else if (index == 3) {
          return !WG_STORE.getPeerPublicKey().empty() ? WG_STORE.getPeerPublicKey() : std::string(tr(STR_NOT_SET));
        } else if (index == 4) {
          return !WG_STORE.getTunnelIP().empty() ? WG_STORE.getTunnelIP() : std::string(tr(STR_NOT_SET));
        } else if (index == 5) {
          return !WG_STORE.getPresharedKey().empty() ? std::string("******") : std::string(tr(STR_NOT_SET));
        } else if (index == 6) {
          return std::string();  // Action item, no value to display
        }
        return std::string(tr(STR_NOT_SET));
      },
      true);

  // Draw help text at bottom
  const auto labels = mappedInput.mapLabels(tr(STR_BACK), tr(STR_SELECT), tr(STR_DIR_UP), tr(STR_DIR_DOWN));
  GUI.drawButtonHints(renderer, labels.btn1, labels.btn2, labels.btn3, labels.btn4);

  renderer.displayBuffer();
}
