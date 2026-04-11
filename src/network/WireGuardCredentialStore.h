#pragma once
#include <string>

class WireGuardCredentialStore;
namespace JsonSettingsIO {
bool saveWireGuard(const WireGuardCredentialStore& store, const char* path);
bool loadWireGuard(WireGuardCredentialStore& store, const char* json, bool* needsResave);
}  // namespace JsonSettingsIO

/**
 * Singleton class for storing WireGuard VPN credentials on the SD card.
 * Private key and preshared key are XOR-obfuscated with the device's unique
 * hardware MAC address and base64-encoded before writing to JSON (not
 * cryptographically secure, but prevents casual reading and ties credentials
 * to the specific device).
 *
 * Heap justification: std::string fields are only allocated when the store is
 * loaded on-demand, saving 224 bytes of always-resident DRAM vs the previous
 * char[] arrays in CrossPointSettings.
 */
class WireGuardCredentialStore {
 private:
  static WireGuardCredentialStore instance;
  std::string endpoint;       // "1.2.3.4:51820" or "vpn.example.com:51820"
  std::string privateKey;     // Base64-encoded 32-byte key (44 chars)
  std::string peerPublicKey;  // Base64-encoded 32-byte key
  std::string tunnelIP;       // Device IP inside tunnel, e.g. "10.0.0.2"
  std::string presharedKey;   // Optional PSK (empty = disabled)

  // Private constructor for singleton
  WireGuardCredentialStore() = default;

  friend bool JsonSettingsIO::saveWireGuard(const WireGuardCredentialStore&, const char*);
  friend bool JsonSettingsIO::loadWireGuard(WireGuardCredentialStore&, const char*, bool*);

 public:
  // Delete copy constructor and assignment
  WireGuardCredentialStore(const WireGuardCredentialStore&) = delete;
  WireGuardCredentialStore& operator=(const WireGuardCredentialStore&) = delete;

  // Get singleton instance
  static WireGuardCredentialStore& getInstance() { return instance; }

  // Save/load from SD card
  bool saveToFile() const;
  bool loadFromFile();

  // Getters
  const std::string& getEndpoint() const { return endpoint; }
  const std::string& getPrivateKey() const { return privateKey; }
  const std::string& getPeerPublicKey() const { return peerPublicKey; }
  const std::string& getTunnelIP() const { return tunnelIP; }
  const std::string& getPresharedKey() const { return presharedKey; }

  // Setters
  void setEndpoint(const std::string& v) { endpoint = v; }
  void setPrivateKey(const std::string& v) { privateKey = v; }
  void setPeerPublicKey(const std::string& v) { peerPublicKey = v; }
  void setTunnelIP(const std::string& v) { tunnelIP = v; }
  void setPresharedKey(const std::string& v) { presharedKey = v; }

  // Check if all required fields are set (endpoint, privateKey, peerPublicKey, tunnelIP)
  bool isConfigured() const {
    return !endpoint.empty() && !privateKey.empty() && !peerPublicKey.empty() && !tunnelIP.empty();
  }
};

// Helper macro to access credential store
#define WG_STORE WireGuardCredentialStore::getInstance()
