"""
Fingerprint-to-Code Generator Engine
Menghasilkan kode unik (Angka / Huruf / Alfanumerik / Password / Token Dinamis)
berdasarkan identitas sidik jari (SID, SubFactor, dan Master Salt).
"""

import hmac
import hashlib
import base64
import os
import json
import time
import string
import struct

CONFIG_DIR = os.path.expanduser(r"~\.fingerprint_code_app")
CONFIG_FILE = os.path.join(CONFIG_DIR, "settings.json")
VAULT_FILE = os.path.join(CONFIG_DIR, "vault.json")

class CodeGenerator:
    def __init__(self):
        self._ensure_config()
        self.settings = self._load_settings()
        self.vault = self._load_vault()

    def _ensure_config(self):
        if not os.path.exists(CONFIG_DIR):
            os.makedirs(CONFIG_DIR, exist_ok=True)

    def _load_settings(self):
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        
        # Default settings
        default_salt = os.urandom(32).hex()
        settings = {
            "master_salt": default_salt,
            "default_format": "alphanumeric_blocks", # numeric_6, numeric_8, numeric_12, alphanumeric_blocks, alphanumeric_16, password_strong, sha256_hex, totp_numeric
            "auto_copy_clipboard": True,
            "mask_display": False,
            "auto_type_keystrokes": False,
        }
        self._save_settings(settings)
        return settings

    def _save_settings(self, settings=None):
        if settings is not None:
            self.settings = settings
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(self.settings, f, indent=4)

    def _load_vault(self):
        if os.path.exists(VAULT_FILE):
            try:
                with open(VAULT_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    def save_vault(self, vault=None):
        if vault is not None:
            self.vault = vault
        with open(VAULT_FILE, "w", encoding="utf-8") as f:
            json.dump(self.vault, f, indent=4)

    def regenerate_master_salt(self):
        """Membuat salt baru agar seluruh kode yang dihasilkan ter-reset secara acak."""
        self.settings["master_salt"] = os.urandom(32).hex()
        self._save_settings()

    def set_custom_finger_code(self, sub_factor, label, custom_code):
        """Menyimpan kode kustom buatan pengguna untuk jari tertentu."""
        key = str(sub_factor)
        self.vault[key] = {
            "label": label,
            "custom_code": custom_code,
            "updated_at": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        self.save_vault()

    def delete_custom_finger_code(self, sub_factor):
        key = str(sub_factor)
        if key in self.vault:
            del self.vault[key]
            self.save_vault()

    def get_custom_finger_code(self, sub_factor):
        return self.vault.get(str(sub_factor), None)

    def _derive_seed(self, sid: str, sub_factor: int, extra_salt: str = "") -> bytes:
        """Menghasilkan seed 32-byte deterministik dari sidik jari."""
        salt = self.settings.get("master_salt", "fingerprint_salt_default").encode("utf-8")
        payload = f"{sid}|{sub_factor}|{extra_salt}".encode("utf-8")
        return hmac.new(salt, payload, hashlib.sha256).digest()

    def generate_code(self, sid: str, sub_factor: int, format_type: str = None) -> dict:
        """
        Mengubah sidik jari menjadi kode angka / huruf sesuai format yang dipilih.
        format_type options:
        - 'numeric_6'             : 6 digit angka (contoh: 849201)
        - 'numeric_8'             : 8 digit angka (contoh: 73910245)
        - 'numeric_12'            : 12 digit angka bertanda hubung (contoh: 8492-3019-4821)
        - 'alphanumeric_blocks'   : 16 karakter huruf & angka (contoh: 8F2A-9K4L-7Z1Q-3M8P)
        - 'alphanumeric_24'       : 24 karakter huruf & angka (contoh: K9X2-M4P8-Q7W1-L3J5-V2B6-N8H4)
        - 'password_strong'       : Password 16 karakter (Huruf Besar, Huruf Kecil, Angka, Simbol)
        - 'sha256_hex'            : Hash heksadesimal 64 karakter
        - 'totp_dynamic_numeric'  : Kode angka 6 digit dinamis (berubah tiap 30 detik)
        - 'custom_vault'          : Kode kustom yang disimpan sendiri oleh user untuk jari ini
        """
        if not format_type:
            format_type = self.settings.get("default_format", "alphanumeric_blocks")

        # Cek jika format custom vault
        custom_entry = self.get_custom_finger_code(sub_factor)
        if format_type == "custom_vault":
            if custom_entry and custom_entry.get("custom_code"):
                return {
                    "format": "custom_vault",
                    "code": custom_entry["custom_code"],
                    "is_custom": True,
                    "label": custom_entry.get("label", "Kode Kustom")
                }
            else:
                format_type = "alphanumeric_blocks"

        seed = self._derive_seed(sid, sub_factor)
        big_int = int.from_bytes(seed, "big")

        code = ""
        description = ""

        if format_type == "numeric_6":
            num = big_int % 1000000
            code = f"{num:06d}"
            description = "PIN 6 Digit Angka"

        elif format_type == "numeric_8":
            num = big_int % 100000000
            code = f"{num:08d}"
            description = "PIN 8 Digit Angka"

        elif format_type == "numeric_12":
            num_str = f"{(big_int % 1000000000000):012d}"
            code = f"{num_str[:4]}-{num_str[4:8]}-{num_str[8:]}"
            description = "Kode 12 Digit Angka"

        elif format_type == "alphanumeric_blocks":
            charset = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ" # Readable chars without ambiguous 0/O, 1/I
            chars = []
            val = big_int
            for _ in range(16):
                chars.append(charset[val % len(charset)])
                val //= len(charset)
            token = "".join(chars)
            code = f"{token[0:4]}-{token[4:8]}-{token[8:12]}-{token[12:16]}"
            description = "Kode Alfanumerik (Huruf & Angka 16 Karakter)"

        elif format_type == "alphanumeric_24":
            charset = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
            chars = []
            val = big_int
            for _ in range(24):
                chars.append(charset[val % len(charset)])
                val //= len(charset)
            token = "".join(chars)
            code = f"{token[0:4]}-{token[4:8]}-{token[8:12]}-{token[12:16]}-{token[16:20]}-{token[20:24]}"
            description = "Kode Alfanumerik Panjang (24 Karakter)"

        elif format_type == "password_strong":
            uppers = string.ascii_uppercase
            lowers = string.ascii_lowercase
            digits = string.digits
            symbols = "!@#$%^&*()-_=+"
            all_chars = uppers + lowers + digits + symbols

            # Jamin minimal 1 uppercase, 1 lowercase, 1 digit, 1 symbol
            val = big_int
            res = [
                uppers[val % len(uppers)],
                lowers[(val >> 8) % len(lowers)],
                digits[(val >> 16) % len(digits)],
                symbols[(val >> 24) % len(symbols)],
            ]
            val = val >> 32
            for _ in range(12):
                res.append(all_chars[val % len(all_chars)])
                val //= len(all_chars)
            code = "".join(res)
            description = "Password Super Kuat (Huruf Besar, Kecil, Angka & Simbol)"

        elif format_type == "sha256_hex":
            code = seed.hex().upper()
            description = "Hash Sidik Jari SHA-256 (64 Karakter)"

        elif format_type == "totp_dynamic_numeric":
            time_step = int(time.time() // 30)
            totp_payload = f"{sid}|{sub_factor}|{time_step}".encode("utf-8")
            totp_hash = hmac.new(seed, totp_payload, hashlib.sha256).digest()
            offset = totp_hash[-1] & 0x0F
            code_int = struct.unpack_from(">I", totp_hash, offset)[0] & 0x7FFFFFFF
            code = f"{(code_int % 1000000):06d}"
            description = "Kode Dinamis TOTP 6 Digit (Berlaku 30 Detik)"

        else:
            # Fallback
            code = f"{(big_int % 1000000):06d}"
            description = "PIN 6 Digit Angka"

        return {
            "format": format_type,
            "code": code,
            "description": description,
            "is_custom": False,
            "custom_available": custom_entry is not None,
            "custom_data": custom_entry
        }

