import os
from utils.token_handler import TOKEN_FILE_PATH

# 🔧 Ortak yapılandırmalar
DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "123",
    "database": "iot"
}

IP_RANGE = "192.168.4.0/24"

def get_base_url():
    """
    stored_token.txt dosyasından base_url bilgisini çeker.
    Eğer dosya yoksa ya da bulunamazsa default URL döner.
    """
    if os.path.exists(TOKEN_FILE_PATH):
        with open(TOKEN_FILE_PATH, "r") as f:
            for line in f:
                if line.startswith("base_url:"):
                    return line.replace("base_url:", "").strip()
    return "https://api.pierenergytrackingsystem.com"  # fallback
