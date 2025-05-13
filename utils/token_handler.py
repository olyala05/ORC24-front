# import os, json, win32api, win32file, requests


# USER_INFO_FILENAME = "user_info.json"
# TOKEN_FILE_PATH = "stored_token.txt"
# LARAVEL_API_URL_V2 = "https://v2.pierenergytrackingsystem.com/api/iot/v2/orc24/dashboard"

# class TokenManager:
#     _token = None

#     @classmethod
#     def load_token(cls):
#         # Zaten yüklendiyse tekrar yükleme
#         if cls._token:
#             return cls._token

#         # Önce stored_token.txt'yi kontrol et
#         if os.path.exists(TOKEN_FILE_PATH):
#             with open(TOKEN_FILE_PATH, "r") as f:
#                 cls._token = f.read().strip()
#                 return cls._token

#         # USB'den okumaya çalış
#         token_data = find_usb_and_read_token()
#         if token_data:
#             token, _ = token_data
#             cls._token = token
#             return cls._token

#         return None

#     @classmethod
#     def get_token(cls):
#         return cls._token or cls.load_token()

#     @classmethod
#     def clear_token(cls):
#         cls._token = None


# # def find_usb_and_read_token():
# #     drives = win32api.GetLogicalDriveStrings().split('\x00')[:-1]
# #     for drive in drives:
# #         if win32file.GetDriveType(drive) == win32file.DRIVE_REMOVABLE:
# #             path = os.path.join(drive, USER_INFO_FILENAME)
# #             if os.path.isfile(path):
# #                 return extract_token_from_file(path)
# #     return None

# def find_usb_and_read_token():
#     print("🔍 USB sürücüleri taranıyor...")
#     drives = win32api.GetLogicalDriveStrings().split('\x00')[:-1]
#     for drive in drives:
#         print(f"📁 Sürücü: {drive}")
#         if win32file.GetDriveType(drive) == win32file.DRIVE_REMOVABLE:
#             print(f"🧲 Taşınabilir sürücü bulundu: {drive}")
#             for root, dirs, files in os.walk(drive):
#                 print(f"📂 Dizin taranıyor: {root}")
#                 for filename in files:
#                     print(f"➡️ Dosya bulundu: {filename}")
#                     if filename.lower().endswith(".pier"):
#                         filepath = os.path.join(root, filename)
#                         print(f"✅ .pier dosyası bulundu: {filepath}")
#                         return extract_token_from_file(filepath)
#     print("🚫 .pier uzantılı dosya bulunamadı.")
#     return None


# # def extract_token_from_file(filepath):
# #     try:
# #         with open(filepath, "r", encoding="utf-8") as file:
# #             data = json.load(file)
# #             token = data.get("auth", {}).get("token")
# #             if token:
# #                 with open(TOKEN_FILE_PATH, "w") as f:
# #                     f.write(token)
# #                 return token, None
# #     except Exception as e:
# #         print(f"Dosya okunamadı: {e}")
# #     return None, None

# def extract_token_from_file(filepath):
#     try:
#         print(f"📄 Dosya okunuyor: {filepath}")
#         with open(filepath, "r", encoding="utf-8") as file:
#             data = json.load(file)
#             token = data.get("auth", {}).get("token")
#             if token:
#                 with open(TOKEN_FILE_PATH, "w") as f:
#                     f.write(token)
#                 print(f"🟢 Token başarıyla yazıldı: {token}")
#                 return token, None
#             else:
#                 print("🚫 Token bulunamadı.")
#     except Exception as e:
#         print(f"❌ Dosya okunamadı veya JSON hatası: {e}")
#     return None, None



# def get_dashboard_data():
#     token = None
#     if os.path.exists(TOKEN_FILE_PATH):
#         with open(TOKEN_FILE_PATH, "r") as f:
#             token = f.read().strip()
#     else:
#         token_data = find_usb_and_read_token()
#         if token_data:
#             token, _ = token_data
#     if not token:
#         return None, "Token bulunamadı"
#     response = requests.get(
#         LARAVEL_API_URL_V2,
#         headers={
#             "Authorization": f"Bearer {token}",
#             "Accept": "application/json",
#             "Content-Type": "application/json"
#         },
#         verify=False
#     )
#     return (response.json(), None) if response.status_code == 200 else (None, f"API hatası: {response.status_code}")

import os
import json
import win32api
import win32file
import requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

TOKEN_FILE_PATH = "stored_token.txt"
AES_KEY = bytes.fromhex("c167ff3136e6a497d7eea9f430080ba9".encode().hex())  # 128-bit key

def decrypt_aes_file(filepath):
    print(f"\nAES şifrelenmiş dosya okunuyor: {filepath}")
    try:
        with open(filepath, "rb") as f:
            encrypted_data = f.read()
            encrypted_data = bytes.fromhex(encrypted_data.decode())

        print(f"Binary veri uzunluğu: {len(encrypted_data)} byte")

        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]

        print(f"IV: {iv.hex()}")
        print(f"Ciphertext örnek: {ciphertext[:16].hex()}...")

        cipher = Cipher(
            algorithms.AES(AES_KEY),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        print("Deşifre başarıyla yapıldı.")
        return plaintext.decode("utf-8")

    except Exception as e:
        print(f"AES çözme hatası: {e}")
        return None

def encrypt_aes_file(data, filepath):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data.encode('utf-8')) + padder.finalize()

    encrypted = encryptor.update(padded_data) + encryptor.finalize()

    with open(filepath, 'wb') as f:
        f.write(iv + encrypted)


def extract_token_from_file(filepath):
    decrypted_json = decrypt_aes_file(filepath)
    print(json.dumps(decrypted_json, indent=4, ensure_ascii=False))
    if not decrypted_json:
        print("Deşifre başarısız.")
        return None, None

    try:
        data = json.loads(decrypted_json)
        token = data.get("auth", {}).get("token")
        base_url = data.get("auth",  {}).get("base_url")

        if token and base_url:
            with open(TOKEN_FILE_PATH, "w") as f:
                f.write(f"token: {token}\nbase_url: {base_url}\n")
            print(f"Token ve base_url yazıldı:\n  token: {token}\n  base_url: {base_url}")
            return token, base_url
        else:
            print("JSON'da token veya base_url eksik.")
    except Exception as e:
        print(f"JSON ayrıştırma hatası: {e}")
    return None, None

def find_usb_and_read_token():
    print("\n🔍 USB sürücüleri taranıyor...")
    drives = win32api.GetLogicalDriveStrings().split('\x00')[:-1]

    for drive in drives:
        print(f"📁 Sürücü: {drive}")
        if win32file.GetDriveType(drive) == win32file.DRIVE_REMOVABLE:
            print(f"🧲 Taşınabilir sürücü bulundu: {drive}")
            for root, _, files in os.walk(drive):
                for filename in files:
                    if filename.lower().endswith(".pier"):
                        filepath = os.path.join(root, filename)
                        print(f"✅ .pier dosyası bulundu: {filepath}")
                        return extract_token_from_file(filepath)

    print("🚫 Herhangi bir .pier dosyası bulunamadı.")
    return None, None

class TokenManager:
    _token = None

    @classmethod
    def load_token(cls):
        print("\n🔁 Token yükleniyor...")

        # Öncelik USB'de! varsa .pier dosyasından al ve stored_token.txt'yi güncelle
        token, _ = find_usb_and_read_token()
        if token:
            cls._token = token
            print("🆕 USB'den token alındı ve stored_token.txt güncellendi.")
            return cls._token

        # USB yoksa stored_token.txt'den devam et
        if os.path.exists(TOKEN_FILE_PATH):
            with open(TOKEN_FILE_PATH, "r") as f:
                for line in f:
                    if line.startswith("token:"):
                        cls._token = line.replace("token:", "").strip()
                        print("📄 Token stored_token.txt içinden alındı.")
                        return cls._token

        print("🚫 Hiçbir yerden token alınamadı.")
        return None


def get_dashboard_data():
    token = TokenManager.load_token()
    base_url = None

    if os.path.exists(TOKEN_FILE_PATH):
        with open(TOKEN_FILE_PATH, "r") as f:
            for line in f:
                if line.startswith("base_url:"):
                    base_url = line.replace("base_url:", "").strip()

    if not token or not base_url:
        return None, "Token veya base_url bulunamadı"

    url = f"{base_url}/orc24/dashboard"  # 🔧 DÜZELTİLEN SATIR
    print(f"📡 Dashboard API çağrısı yapılıyor: {url}")

    try:
        response = requests.get(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
                "Content-Type": "application/json"
            },
            verify=False
        )
        if response.status_code == 200:
            return response.json(), None
        else:
            return None, f"API hatası: {response.status_code}"
    except Exception as e:
        return None, f"İstek hatası: {e}"
