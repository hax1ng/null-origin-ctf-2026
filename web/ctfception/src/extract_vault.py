#!/usr/bin/env python3
"""
Archive Vault Extractor // CTFception - Tilak Historical Chronicles
Preserved by Archivist: PRX02

Usage:
    python extract_vault.py <password>
Example:
    python extract_vault.py gitarahasya
"""

import sys
import os

try:
    import pyzipper
except ImportError:
    print("[!] 'pyzipper' library not found. Installing pyzipper...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pyzipper"])
    import pyzipper

def extract_archive(zip_filename, password):
    if not os.path.exists(zip_filename):
        print(f"[!] Archive '{zip_filename}' not found in current directory.")
        return False

    try:
        with pyzipper.AESZipFile(zip_filename, 'r') as zf:
            zf.setpassword(password.encode("utf-8"))
            extract_dir = "kesari_vault_contents"
            os.makedirs(extract_dir, exist_ok=True)
            zf.extractall(path=extract_dir)
            print("=" * 60)
            print(f"[+] Archive successfully unlocked with password: '{password}'")
            print(f"[+] Extracted files to ./{extract_dir}/:")
            for item in zf.namelist():
                print(f"    -> {item}")
            print("=" * 60)
            print("[*] Read MANDALAY_DISPATCH_1908.txt for the next cipher step.")
            return True
    except Exception as e:
        print(f"[-] Extraction failed: {e}")
        print("[*] Hint: The password is the lowercase Marathi title of Tilak's philosophical magnum opus written in Mandalay jail (11 letters, no spaces).")
        return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        pwd = input("[?] Enter archive passphrase: ").strip()
    else:
        pwd = sys.argv[1].strip()

    vault_file = os.path.join(os.path.dirname(__file__), "kesari_vault_1908.zip")
    if not os.path.exists(vault_file):
        vault_file = "kesari_vault_1908.zip"

    extract_archive(vault_file, pwd)

