#!/usr/bin/env python3
"""
Build wrapper for environments with SSL proxy issues (e.g., corporate proxies
with self-signed certificates). This script:

1. Patches SSL verification at the Python requests layer
2. Runs `pio run`, which installs libraries from GitHub URLs
   (configured via platformio.local.ini)
3. Applies post-install patches to libraries with API incompatibilities
4. Retries the build after patching

Usage:
    python3 scripts/build_wrapper.py

Requires: platformio.local.ini with lib_deps overriding registry URLs
          to direct GitHub archive URLs.
"""
import os
import sys

# Patch SSL at the requests adapter level before any PlatformIO imports
import requests.adapters

_orig_send = requests.adapters.HTTPAdapter.send


def _patched_send(self, request, stream=False, timeout=None,
                  verify=True, cert=None, proxies=None):
    return _orig_send(self, request, stream=stream, timeout=timeout,
                      verify=False, cert=cert, proxies=proxies)


requests.adapters.HTTPAdapter.send = _patched_send

import urllib3
urllib3.disable_warnings()

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def apply_patches():
    """Apply necessary patches to downloaded libraries."""
    libdeps_dir = os.path.join(PROJECT_DIR, ".pio", "libdeps")
    if not os.path.isdir(libdeps_dir):
        return False

    patched = False

    for env_dir in os.listdir(libdeps_dir):
        env_path = os.path.join(libdeps_dir, env_dir)
        if not os.path.isdir(env_path):
            continue

        # Patch PNGdec: callback return type void -> int
        # PNGdec 1.0.3 uses void, but project code expects int (as in master)
        pngdec_header = os.path.join(env_path, "PNGdec", "src", "PNGdec.h")
        if os.path.exists(pngdec_header):
            with open(pngdec_header, 'r') as f:
                content = f.read()
            if "typedef void (PNG_DRAW_CALLBACK)" in content:
                content = content.replace(
                    "typedef void (PNG_DRAW_CALLBACK)",
                    "typedef int (PNG_DRAW_CALLBACK)"
                )
                with open(pngdec_header, 'w') as f:
                    f.write(content)
                print(f"  Patched PNGdec callback type in {env_dir}")
                patched = True

        # Remove JPEGDisplay files (requires external bb_spi_lcd.h)
        jpegdec_dir = os.path.join(env_path, "JPEGDEC")
        if os.path.isdir(jpegdec_dir):
            for root, dirs, files in os.walk(jpegdec_dir):
                for fname in files:
                    if fname.startswith("JPEGDisplay"):
                        os.remove(os.path.join(root, fname))
                        print(f"  Removed {fname} from JPEGDEC in {env_dir}")
                        patched = True

        # Fix SdFat owner metadata for dependency resolution
        sdfat_piopm = os.path.join(env_path, "SdFat", ".piopm")
        if os.path.exists(sdfat_piopm):
            import json
            with open(sdfat_piopm) as f:
                data = json.load(f)
            if data.get("spec", {}).get("owner") is None:
                data["spec"]["owner"] = "greiman"
                with open(sdfat_piopm, 'w') as f:
                    json.dump(data, f)
                print(f"  Fixed SdFat owner metadata in {env_dir}")
                patched = True

    return patched


def main():
    from platformio.__main__ import main as pio_main

    print("Applying library patches...")
    apply_patches()

    print("Running PlatformIO build...")
    sys.argv = ['pio', 'run'] + sys.argv[1:]
    try:
        pio_main()
    except SystemExit as e:
        if e.code != 0:
            print("\nBuild failed. Applying patches and retrying...")
            if apply_patches():
                sys.argv = ['pio', 'run'] + sys.argv[1:]
                pio_main()
            else:
                sys.exit(e.code)


if __name__ == "__main__":
    main()
