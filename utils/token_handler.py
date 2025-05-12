import os, json, win32api, win32file, requests

USER_INFO_FILENAME = "user_info.json"
TOKEN_FILE_PATH = "stored_token.txt"
LARAVEL_API_URL_V2 = "https://v2.pierenergytrackingsystem.com/api/iot/v2/orc24/dashboard"

class TokenManager:
    _token = None

    @classmethod
    def load_token(cls):
        # Zaten yüklendiyse tekrar yükleme
        if cls._token:
            return cls._token

        # Önce stored_token.txt'yi kontrol et
        if os.path.exists(TOKEN_FILE_PATH):
            with open(TOKEN_FILE_PATH, "r") as f:
                cls._token = f.read().strip()
                return cls._token

        # USB'den okumaya çalış
        token_data = find_usb_and_read_token()
        if token_data:
            token, _ = token_data
            cls._token = token
            return cls._token

        return None

    @classmethod
    def get_token(cls):
        return cls._token or cls.load_token()

    @classmethod
    def clear_token(cls):
        cls._token = None


def find_usb_and_read_token():
    drives = win32api.GetLogicalDriveStrings().split('\x00')[:-1]
    for drive in drives:
        if win32file.GetDriveType(drive) == win32file.DRIVE_REMOVABLE:
            path = os.path.join(drive, USER_INFO_FILENAME)
            if os.path.isfile(path):
                return extract_token_from_file(path)
    return None

def extract_token_from_file(filepath):
    try:
        with open(filepath, "r", encoding="utf-8") as file:
            data = json.load(file)
            token = data.get("auth", {}).get("token")
            if token:
                with open(TOKEN_FILE_PATH, "w") as f:
                    f.write(token)
                return token, None
    except Exception as e:
        print(f"Dosya okunamadı: {e}")
    return None, None

def get_dashboard_data():
    token = None
    if os.path.exists(TOKEN_FILE_PATH):
        with open(TOKEN_FILE_PATH, "r") as f:
            token = f.read().strip()
    else:
        token_data = find_usb_and_read_token()
        if token_data:
            token, _ = token_data
    if not token:
        return None, "Token bulunamadı"
    response = requests.get(
        LARAVEL_API_URL_V2,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Content-Type": "application/json"
        },
        verify=False
    )
    return (response.json(), None) if response.status_code == 200 else (None, f"API hatası: {response.status_code}")