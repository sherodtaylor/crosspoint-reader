"""
Vendor the wireguard-lwip component from microlink into lib/WireGuard/.

Fetches the latest wireguard_lwip component from CamM2325/microlink,
flattens it into PlatformIO-compatible layout, and writes library.json.

Run manually: python3 scripts/vendor_wireguard.py

Idempotent — skips if lib/WireGuard/wireguard.c already exists.
"""

import os
import shutil
import subprocess
import sys

REPO_URL = "https://github.com/CamM2325/microlink.git"
COMPONENT_PATH = "components/microlink/components/wireguard_lwip"
DEST_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "lib", "WireGuard")

# Files to copy from src/ (flattened to root)
SRC_FILES = [
    "wireguard.c", "wireguard.h",
    "wireguardif.c", "wireguardif.h",
    "wireguard-platform.h",
    "wireguard-platform-esp32.c",
    "crypto.c", "crypto.h",
    "lwip_compat.h",
]

# Crypto reference implementations (keep in crypto/refc/ subdirectory)
CRYPTO_FILES = [
    "blake2s.c", "blake2s.h",
    "chacha20.c", "chacha20.h",
    "chacha20poly1305.c", "chacha20poly1305.h",
    "poly1305-donna.c", "poly1305-donna.h", "poly1305-donna-32.h",
    "x25519.c", "x25519.h",
]

# Excluded: crypto/cortex/* (ARM assembly, wrong arch for RISC-V ESP32-C3)

LIBRARY_JSON = """{
  "name": "WireGuard",
  "version": "0.1.0",
  "description": "WireGuard VPN client for ESP32 (from microlink/wireguard-lwip, BSD-3-Clause)",
  "license": "BSD-3-Clause",
  "frameworks": "arduino",
  "platforms": "espressif32",
  "build": {
    "srcFilter": ["+<*.c>", "+<crypto/refc/*.c>"]
  }
}
"""


def vendor():
    # Skip if already vendored
    if os.path.isfile(os.path.join(DEST_DIR, "wireguard.c")):
        print("WireGuard library already vendored — skipping")
        return

    print("Vendoring wireguard-lwip from microlink...")

    # Clone to temp dir
    tmp_dir = os.path.join(os.path.dirname(DEST_DIR), ".wireguard-vendor-tmp")
    if os.path.isdir(tmp_dir):
        shutil.rmtree(tmp_dir)

    subprocess.check_call(
        ["git", "clone", "--depth", "1", REPO_URL, tmp_dir],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )

    src_dir = os.path.join(tmp_dir, COMPONENT_PATH, "src")
    crypto_src = os.path.join(src_dir, "crypto", "refc")

    # Create destination
    crypto_dest = os.path.join(DEST_DIR, "crypto", "refc")
    os.makedirs(crypto_dest, exist_ok=True)

    # Copy and flatten src files to lib/WireGuard/
    for f in SRC_FILES:
        src = os.path.join(src_dir, f)
        dst = os.path.join(DEST_DIR, f)
        if os.path.isfile(src):
            shutil.copy2(src, dst)
        else:
            print(f"WARNING: {f} not found in upstream")

    # Rename platform file to generic name
    esp32_plat = os.path.join(DEST_DIR, "wireguard-platform-esp32.c")
    generic_plat = os.path.join(DEST_DIR, "wireguard-platform.c")
    if os.path.isfile(esp32_plat) and not os.path.isfile(generic_plat):
        os.rename(esp32_plat, generic_plat)

    # Copy crypto reference implementations
    for f in CRYPTO_FILES:
        src = os.path.join(crypto_src, f)
        dst = os.path.join(crypto_dest, f)
        if os.path.isfile(src):
            shutil.copy2(src, dst)
        else:
            print(f"WARNING: crypto/refc/{f} not found in upstream")

    # Write library.json
    with open(os.path.join(DEST_DIR, "library.json"), "w") as fh:
        fh.write(LIBRARY_JSON)

    # Cleanup
    shutil.rmtree(tmp_dir)

    print(f"Vendored wireguard-lwip to {DEST_DIR}")
    print(f"  {len(SRC_FILES)} core files + {len(CRYPTO_FILES)} crypto files")


if __name__ == "__main__":
    vendor()
else:
    # PlatformIO pre-build script mode
    try:
        Import("env")  # noqa: F821
        vendor()
    except NameError:
        vendor()
