# from flask import (
#     Blueprint,
#     request,
#     session,
#     redirect,
#     url_for,
#     flash,
#     render_template,
#     jsonify,
# )
# import requests
# from datetime import datetime, timedelta
# import json
# from utils.token_handler import get_dashboard_data, find_usb_and_read_token
# from pprint import pprint
# import os
# from utils.token_handler import TokenManager

# auth_bp = Blueprint("auth", __name__)

# LARAVEL_API_URL = "https://v2.pierenergytrackingsystem.com/api/iot/v2/orc24/whoami"
# USER_INFO_FILENAME = "user_info.json"
# TOKEN_FILE_PATH = "stored_token.txt"

# # Giriş Sayfası
# from utils.token_handler import get_dashboard_data, TOKEN_FILE_PATH

# @auth_bp.route("/login", methods=["GET", "POST"])
# def login():
#     print("🟢 [Login Fonksiyonu Çalıştı]")

#     if 'lang' not in session:
#         session['lang'] = 'en'

#     if request.method == "POST":
#         print("[POST İsteği Alındı]")

#         email = request.form.get("email").strip()
#         password = request.form.get("password").strip()

#         # TOKEN'I ALIYORUZ
#         if os.path.exists(TOKEN_FILE_PATH):
#             with open(TOKEN_FILE_PATH, "r") as f:
#                 token = f.read().strip()
#         else:
#             token_data = find_usb_and_read_token()  
#             if token_data:
#                 token, _ = token_data
#             else:
#                 flash("Token bulunamadı!", "danger")
#                 return redirect(url_for("auth.login"))

#         print(f"[Kullanılan Token]: {token}")
#         print(f"[DEBUG Token repr()]: {repr(token)}")  # Boşluk / newline kontrolü

#         # API'ye istek atılıyor
#         print("[API İsteği Gönderiliyor]")
#         response = requests.post(
#             LARAVEL_API_URL,
#             data=json.dumps({"username": email, "password": password}),
#             headers={
#                 "Authorization": f"Bearer {token}",
#                 "Accept": "application/json",
#                 "Content-Type": "application/json",
#                 "User-Agent": "PostmanRuntime/7.43.3"
#             },
#             verify=False,
#         )

#         try:
#             pprint(response.json())
#         except Exception as e:
#             print(f"JSON parse hatası: {e}")
#             print(response.text)

#         if response.status_code == 200:
#             print("[Login Başarılı]")

#             session["client_name"] = response.json().get("client", {}).get("name")
#             session["client_role"] = response.json().get("client", {}).get("role")
#             session["access_token"] = token
#             session["login_success"] = True
#             session["login_time"] = datetime.utcnow().isoformat()

#             print("[Modem Seçim Sayfasına Yönlendiriliyor]")
#             return redirect(url_for("modem_selection"))

#         print(f"[Login Başarısız] Status: {response.status_code}")
#         flash("Hatalı e-posta veya şifre veya token!", "danger")
#         return redirect(url_for("auth.login"))

#     print("[GET İsteği - Login Sayfası Açılıyor]")
#     login_success = session.pop("login_success", None)
#     return render_template("login.html", login_success=login_success)

# # Login Butonuna Basıldığında Yönlendirme Kontrolü için endpoint
# @auth_bp.route("/check-login-redirect")
# def check_login_redirect():
#     login_time_str = session.get("login_time")

#     if login_time_str:
#         login_time = datetime.fromisoformat(login_time_str)
#         now = datetime.utcnow()
#         time_diff = now - login_time

#         if time_diff < timedelta(hours=2):
#             return redirect(url_for("modem_selection"))
#         else:
#             session.clear()
#     return redirect(url_for("auth.login"))

# @auth_bp.route("/auto-login", methods=["POST"])
# def auto_login():
#     print("Auto-login başladı")
#     data, error = get_dashboard_data()

#     if error:
#         print(f"❌ Auto-login Hatası: {error}")   
#         return jsonify({"success": False, "message": error}), 403

#     print("🔹 API'den gelen veriler:", json.dumps(data, indent=2))
#     return jsonify({"success": True, "data": data})


# @auth_bp.route("/logout", methods=["POST"])
# def logout():
#     session.clear()
#     return redirect(url_for("dashboard.dashboard"))



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
from pprint import pprint
import os

from utils.token_handler import (
    get_dashboard_data,
    find_usb_and_read_token,
    TOKEN_FILE_PATH,
    TokenManager
)

auth_bp = Blueprint("auth", __name__)
USER_INFO_FILENAME = "user_info.json"

# Base URL ve token'ı stored_token.txt'den oku
def get_token_and_base_url():
    token = None
    base_url = None

    if os.path.exists(TOKEN_FILE_PATH):
        with open(TOKEN_FILE_PATH, "r") as f:
            for line in f:
                if line.startswith("token:"):
                    token = line.replace("token:", "").strip()
                elif line.startswith("base_url:"):
                    base_url = line.replace("base_url:", "").strip()
    else:
        token_data = find_usb_and_read_token()
        if token_data:
            token, base_url = token_data

    return token, base_url


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    print("🟢 [Login Fonksiyonu Çalıştı]")

    if 'lang' not in session:
        session['lang'] = 'en'

    if request.method == "POST":
        print("[POST İsteği Alındı]")

        email = request.form.get("email").strip()
        password = request.form.get("password").strip()

        token, base_url = get_token_and_base_url()
        if not token or not base_url:
            flash("Token veya base URL bulunamadı!", "danger")
            return redirect(url_for("auth.login"))

        print(f"[Kullanılan Token]: {token}")
        print(f"[Kullanılan Base URL]: {base_url}")
        print(f"[DEBUG Token repr()]: {repr(token)}")  

        # API isteği hazırlanıyor
        whoami_url = f"{base_url}/api/iot/v2/orc24/whoami"
        print(f"[API İsteği]: {whoami_url}")

        response = requests.post(
            whoami_url,
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

        print(f"[Login Başarısız] Status: {response.status_code}")
        flash("Hatalı e-posta, şifre veya token!", "danger")
        return redirect(url_for("auth.login"))

    print("[GET İsteği - Login Sayfası Açılıyor]")
    login_success = session.pop("login_success", None)
    return render_template("login.html", login_success=login_success)


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
        print(f"❌ Auto-login Hatası: {error}")
        return jsonify({"success": False, "message": error}), 403

    print("🔹 API'den gelen veriler:", json.dumps(data, indent=2))
    return jsonify({"success": True, "data": data})


@auth_bp.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("dashboard.dashboard"))
