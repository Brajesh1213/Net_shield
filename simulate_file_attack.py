"""
simulate_file_attack.py — Tests NetSentinel's File Monitor detection capabilities.

This script creates fake malicious files in your Downloads folder to verify
that the FileMonitor catches:
  1. Steganography (EXE hidden inside image files)
  2. Suspicious executable drops
  3. Malicious script drops (.bat, .ps1, .vbs)

IMPORTANT: These are HARMLESS test files — they contain no real malware.
           They only have the right byte signatures to trigger detection.

Usage:  python simulate_file_attack.py
"""

import os
import time
import sys

DOWNLOADS = os.path.join(os.environ["USERPROFILE"], "Downloads")

# ── Test files to create ────────────────────────────────────────────────────────
# Each entry: (filename, description, raw bytes content)
#
# The MZ header (0x4D 0x5A) is the Windows PE executable signature.
# Legitimate images start with their own magic bytes (JPEG=FF D8 FF, PNG=89 50 4E 47).
# If an "image" starts with MZ instead, it's a disguised executable.

TEST_FILES = [
    # ─── Attack 1: EXE disguised as JPEG (steganography) ───────────────────
    (
        "vacation_photo.jpg",
        "Steganography — EXE hidden inside a .jpg file",
        # MZ header = Windows PE executable, NOT a real JPEG
        b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
        b"\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00"
        b"This program cannot be run in DOS mode.\r\n"
        b"FAKE_MALWARE_PAYLOAD_FOR_TESTING_ONLY"
    ),

    # ─── Attack 2: EXE disguised as PNG (steganography) ───────────────────
    (
        "screenshot_2026.png",
        "Steganography — EXE hidden inside a .png file",
        # MZ header again, but with .png extension
        b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
        b"\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00"
        b"FAKE_PNG_STEGANOGRAPHY_TEST"
    ),

    # ─── Attack 3: Corrupted GIF (wrong magic bytes, not MZ but not valid GIF) ─
    (
        "funny_meme.gif",
        "Steganography — File claims to be .gif but has wrong magic bytes",
        # Neither GIF magic (47 49 46) nor MZ — just garbage pretending to be GIF
        b"\x00\x01\x02\x03\x04\x05\x06\x07"
        b"NOT_A_REAL_GIF_FILE_SUSPICIOUS_CONTENT"
    ),

    # ─── Attack 4: Malicious batch script drop ─────────────────────────────
    (
        "windows_update_fix.bat",
        "Script drop — .bat file appeared in Downloads",
        b"@echo off\r\n"
        # b"REM FAKE malware test — this file is harmless\r\n"
        b"echo TEST ONLY - NetSentinel should detect this\r\n"
        b"pause\r\n"
    ),

    # ─── Attack 5: Suspicious executable drop ──────────────────────────────
    (
        "free_game_crack.exe",
        "Suspicious drop — .exe appeared in Downloads",
        b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
        b"FAKE_EXECUTABLE_FOR_TESTING_NETSENTINEL_DETECTION"
    ),

    # ─── Attack 6: PowerShell script drop ──────────────────────────────────
    (
        "system_cleanup.ps1",
        "Script drop — .ps1 PowerShell file appeared in Downloads",
        b"# FAKE PowerShell malware test\r\n"
        b"# NetSentinel should flag this as SCRIPT_DROP\r\n"
        b"Write-Host 'This is a harmless test file'\r\n"
    ),
]


def banner():
    print("=" * 65)
    print("  NetSentinel File Attack Simulator")
    print("  Tests: Steganography, Malware Drops, Script Drops")
    print("=" * 65)
    print(f"  Target folder: {DOWNLOADS}")
    print(f"  Files to drop : {len(TEST_FILES)}")
    print("=" * 65)
    print()


def drop_file(filename, description, content):
    path = os.path.join(DOWNLOADS, filename)
    print(f"  [ATTACK] {description}")
    print(f"           Dropping: {filename} ({len(content)} bytes)")
    with open(path, "wb") as f:
        f.write(content)
    print(f"           Created:  {path}")
    print()


def cleanup(files_created):
    print("\n" + "-" * 65)
    input("  Press ENTER to clean up test files...")
    print()
    for path in files_created:
        try:
            os.remove(path)
            print(f"  [CLEANUP] Deleted: {os.path.basename(path)}")
        except FileNotFoundError:
            print(f"  [CLEANUP] Already gone: {os.path.basename(path)}")
        except PermissionError:
            print(f"  [CLEANUP] Locked (may have been quarantined): {os.path.basename(path)}")
    print("\n  All test files cleaned up.")
    print("=" * 65)


def main():
    banner()

    if not os.path.isdir(DOWNLOADS):
        print(f"  [ERROR] Downloads folder not found: {DOWNLOADS}")
        sys.exit(1)

    print("  Make sure NetSentinel is running before proceeding!")
    print()
    input("  Press ENTER to start the attack simulation...")
    print()

    files_created = []
    for i, (filename, description, content) in enumerate(TEST_FILES, 1):
        print(f"  ── Attack {i}/{len(TEST_FILES)} ──")
        path = os.path.join(DOWNLOADS, filename)
        drop_file(filename, description, content)
        files_created.append(path)

        if i < len(TEST_FILES):
            print(f"  Waiting 3 seconds before next attack...\n")
            time.sleep(3)

    print("=" * 65)
    print("  All attacks executed!")
    print()
    print("  Check NetSentinel for these alerts:")
    print("    - STEGANOGRAPHY ALERT  (vacation_photo.jpg)")
    print("    - STEGANOGRAPHY ALERT  (screenshot_2026.png)")
    print("    - STEGANOGRAPHY ALERT  (funny_meme.gif)")
    print("    - MALWARE DROP         (windows_update_fix.bat)")
    print("    - MALWARE DROP         (free_game_crack.exe)")
    print("    - MALWARE DROP         (system_cleanup.ps1)")
    print("=" * 65)

    cleanup(files_created)


if __name__ == "__main__":
    main()
