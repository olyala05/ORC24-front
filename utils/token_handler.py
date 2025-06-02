# Gerekli kütüphaneleri içe aktar
import os  # dosya işlemleri
import json  # json dosyalarıyla çalışmak için
import win32api  # Windows sürücülerini bulmak için
import win32file  # USB tipi sürücüleri bulmak için
import requests  # web istekleri yapmak için
import socket  # ip adresi almak için
import uuid  # mac adresi almak için
import pika  # RabbitMQ bağlantısı için

# Şifreleme için kütüphaneler
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Token dosyasının adı
TOKEN_FILE_PATH = "stored_token.txt"

# AES şifre çözmek için anahtar
AES_KEY = bytes.fromhex("c167ff3136e6a497d7eea9f430080ba9".encode().hex())

# AES ile şifre çözme
def decrypt_aes_file(filepath):
    print(f"\nAES şifrelenmiş dosya okunuyor: {filepath}")
    try:
        with open(filepath, "rb") as f:
            encrypted_data = f.read()
            encrypted_data = bytes.fromhex(encrypted_data.decode())

        iv = encrypted_data[:16]  # başlangıç verisi
        ciphertext = encrypted_data[16:]  # şifreli veri

        cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        return plaintext.decode("utf-8")
    except Exception as e:
        print(f"AES çözme hatası: {e}")
        return None

# AES ile şifreleme
def encrypt_aes_file(data, filepath):
    iv = os.urandom(16)  # rastgele iv
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data.encode('utf-8')) + padder.finalize()

    encrypted = encryptor.update(padded_data) + encryptor.finalize()

    with open(filepath, 'wb') as f:
        f.write(iv + encrypted)

# .pier dosyasından token ve url çıkar
def extract_token_from_file(filepath):
    decrypted_json = decrypt_aes_file(filepath)

    if not decrypted_json:
        print("❌ Deşifre başarısız.")
        return None, None

    try:
        data = json.loads(decrypted_json)

        token = data.get("auth", {}).get("token")
        base_url = data.get("auth", {}).get("base_url")
        rabbitmq_info = data.get("rabbit_mq", {})

        if token and base_url:
            with open(TOKEN_FILE_PATH, "w") as f:
                f.write(f"token: {token}\n")
                f.write(f"base_url: {base_url}\n")

                # RabbitMQ bilgilerini dosyaya yaz
                expected_keys = [
                    "url", "host", "port", "port_ssl", "user",
                    "password", "vhost", "channel", "ssl_ca_cert", "connection_name"
                ]

                for key in expected_keys:
                    value = rabbitmq_info.get(key)
                    clean_value = str(value).strip() if value is not None else ""
                    f.write(f"rabbit_{key}: {clean_value}\n")

            print("✅ Token, base_url ve RabbitMQ bilgileri dosyaya yazıldı.")
            return token, base_url
        else:
            print("⚠️ JSON'da token veya base_url eksik.")
    except Exception as e:
        print(f"❌ JSON ayrıştırma hatası: {e}")

    return None, None

# USB sürücüsünde .pier dosyası ara
def find_usb_and_read_token():
    print("\n🔍 USB sürücüleri taranıyor...")
    drives = win32api.GetLogicalDriveStrings().split('\x00')[:-1]

    for drive in drives:
        if win32file.GetDriveType(drive) == win32file.DRIVE_REMOVABLE:
            for root, _, files in os.walk(drive):
                for filename in files:
                    if filename.lower().endswith(".pier"):
                        filepath = os.path.join(root, filename)
                        return extract_token_from_file(filepath)

    print("🚫 Herhangi bir .pier dosyası bulunamadı.")
    return None, None

# Token bilgisini yöneten sınıf
class TokenManager:
    _token = None

    @classmethod
    def load_token(cls):
        print("\n🔁 Token yükleniyor...")

        # Önce USB'den dene
        token, _ = find_usb_and_read_token()
        if token:
            cls._token = token
            return cls._token

        # Dosyadan dene
        if os.path.exists(TOKEN_FILE_PATH):
            with open(TOKEN_FILE_PATH, "r") as f:
                for line in f:
                    if line.startswith("token:"):
                        cls._token = line.replace("token:", "").strip()
                        return cls._token

        print("🚫 Token bulunamadı.")
        return None

# Dashboard verisini API'den çek
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

    url = f"{base_url}/orc24/dashboard"

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

# RabbitMQ için mesaj hazırla
def build_modem_message(token):
    local_ip = socket.gethostbyname(socket.gethostname())
    mac = ':'.join(['{:02X}'.format((uuid.getnode() >> i) & 0xff) for i in range(0, 8 * 6, 8)][::-1])

    message = {
        "token": token,
        "type": "modem",
        "version": 2,
        "content": {
            "vpn_ip_address": "10.8.0.10",
            "local_ip_address": local_ip,
            "public_ip_address": "8.8.8.8",
            "mac_address": mac,
            "end_mac_address": mac,
            "operation_system_id": 1,
            "model_id": 1,
            "brand_type_id": 2,
            "communication_protocol_id": 1,
            "network_type_id": 2,
            "communication_type_id": 1,
            "version": "1.0.0",
            "temperature_data": 0.0,
            "cpu_usage": 0.0,
            "total_memory": 0.0,
            "used_memory": 0.0
        }
    }

    return json.dumps(message)

# RabbitMQ'ya mesaj gönder
def send_rabbitmq_modem_message(token):
    print("\n📦 RabbitMQ modem mesajı gönderiliyor...")

    if not os.path.exists(TOKEN_FILE_PATH):
        return False, "stored_token.txt bulunamadı"

    rabbit_info = {}
    with open(TOKEN_FILE_PATH, "r") as f:
        for line in f:
            if line.startswith("rabbit_"):
                try:
                    key, value = line.strip().split(":", 1)
                    rabbit_info[key.replace("rabbit_", "").strip()] = value.strip()
                except ValueError:
                    pass

    # Gerekli bilgiler varsa bağlan
    required_keys = ["host", "port", "user", "password", "channel"]
    for rk in required_keys:
        if rk not in rabbit_info or not rabbit_info[rk]:
            return False, f"Gerekli bilgi eksik: {rk}"

    try:
        credentials = pika.PlainCredentials(rabbit_info["user"], rabbit_info["password"])
        params = pika.ConnectionParameters(
            host=rabbit_info["host"],
            port=int(rabbit_info["port"]),
            virtual_host=rabbit_info.get("vhost", "/"),
            credentials=credentials,
            heartbeat=10,
            blocked_connection_timeout=5
        )

        connection = pika.BlockingConnection(params)
        channel = connection.channel()

        message = build_modem_message(token)
        channel.basic_publish(
            exchange="",
            routing_key=rabbit_info["channel"],
            body=message.encode("utf-8")
        )

        connection.close()
        return True, "Mesaj gönderildi"
    except Exception as e:
        return False, str(e)

