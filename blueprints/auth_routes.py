from flask import (
    Blueprint,
    request,
    session,
    redirect,
    url_for,
    flash,
    render_template,
    jsonify,
)
import requests
from datetime import datetime, timedelta
import json
from utils.token_handler import get_dashboard_data, find_usb_and_read_token_windows
from pprint import pprint
import os

auth_bp = Blueprint("auth", __name__)

# LOGIN API
# LARAVEL_API_URL = "https://api.pierenergytrackingsystem.com/v1/orc24"

LARAVEL_API_URL = "https://v2.pierenergytrackingsystem.com/api/iot/v2/orc24/whoami"
USER_INFO_FILENAME = "user_info.json"
TOKEN_FILE_PATH = "stored_token.txt"

# Giriş Sayfası
from utils.token_handler import get_dashboard_data, TOKEN_FILE_PATH

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    print("🟢 [Login Fonksiyonu Çalıştı]")

    if request.method == "POST":
        print("[POST İsteği Alındı]")

        email = request.form.get("email").strip()
        password = request.form.get("password").strip()

        # TOKEN'I ALIYORUZ
        if os.path.exists(TOKEN_FILE_PATH):
            with open(TOKEN_FILE_PATH, "r") as f:
                token = f.read().strip()
        else:
            token_data = find_usb_and_read_token_windows()
            if token_data:
                token, _ = token_data
            else:
                flash("Token bulunamadı!", "danger")
                return redirect(url_for("auth.login"))

        print(f"[Kullanılan Token]: {token}")

        # API'ye istek atılıyor
        print("[API İsteği Gönderiliyor]")
        response = requests.post(
            LARAVEL_API_URL,
            data=json.dumps({"username": email, "password": password}),
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": "PostmanRuntime/7.43.3"
            },
            verify=False,
        )
        try:
            pprint(response.json())
        except Exception as e:
            print(f"JSON parse hatası: {e}")
            print(response.text)

        if response.status_code == 200:
            print("[Login Başarılı]")

            session["client_name"] = response.json().get("client", {}).get("name")
            session["client_role"] = response.json().get("client", {}).get("role")
            session["access_token"] = token
            session["login_success"] = True
            session["login_time"] = datetime.utcnow().isoformat()

            print("[Modem Seçim Sayfasına Yönlendiriliyor]")
            return redirect(url_for("modem_selection"))

        print("[Login Başarısız] Hatalı e-posta, şifre veya token!")
        flash("Hatalı e-posta veya şifre", "danger")
        return redirect(url_for("auth.login"))

    print("[GET İsteği - Login Sayfası Açılıyor]")
    login_success = session.pop("login_success", None)
    return render_template("login.html", login_success=login_success)


# Login Butonuna Basıldığında Yönlendirme Kontrolü için endpoint
@auth_bp.route("/check-login-redirect")
def check_login_redirect():
    login_time_str = session.get("login_time")

    if login_time_str:
        login_time = datetime.fromisoformat(login_time_str)
        now = datetime.utcnow()
        time_diff = now - login_time

        if time_diff < timedelta(hours=2):
            return redirect(url_for("modem_selection"))
        else:
            session.clear()
    return redirect(url_for("auth.login"))


@auth_bp.route("/auto-login", methods=["POST"])
def auto_login():
    print("Auto-login başladı")
    data, error = get_dashboard_data()

    if error:
        return jsonify({"success": False, "message": error}), 403

    print("🔹 API'den gelen veriler:", json.dumps(data, indent=2))
    return jsonify({"success": True, "data": data})


@auth_bp.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("auth.login"))
