import requests
from flask import Flask, render_template, request,  jsonify, redirect, url_for, session, flash
from flask_jwt_extended import JWTManager, create_access_token
from flask_cors import CORS
from flask_scss import Scss
import json

app = Flask(__name__)
CORS(app)
app.secret_key = 'supersecretkey'
app.config["JWT_SECRET_KEY"] = "jwt_secret_key"
jwt = JWTManager(app)

# Laravel API'nin URL'si 
LARAVEL_API_URL = "https://api.pierenergytrackingsystem.com/v1"

# Flask-SCSS'i başlat
Scss(app, static_dir='static', asset_dir='assets')

@app.route('/')
def index():
    return render_template("index.html")


# 🎯 Giriş Sayfası
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        print("Giriş Denemesi:", email, password)

        response = requests.get(
            f"{LARAVEL_API_URL}/orc24/login",
            params={"client_email": email, "client_password": password},
            headers={"Accept": "application/json"},
            verify=False
        )

        print("Laravel API Yanıtı:", response.status_code, response.text)

        if response.status_code == 200:
            try:
                api_response = response.json()
                session["access_token"] = api_response.get("access_token")

                flash("Giriş başarılı!", "success")
                return redirect(url_for("dashboard"))  # 🎯 Başarılı giriş sonrası yönlendir
            except Exception as e:
                print("JSON Decode Hatası:", e)
                flash("Sunucudan geçersiz yanıt alındı!", "danger")
                return redirect(url_for("login"))

        flash("Hatalı e-posta veya şifre!", "danger")
        return redirect(url_for("login"))

    return render_template("login.html")  # 🎯 Eğer GET isteği yapılırsa login sayfasını göster

# # 🎯 Dashboard Sayfası
@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")

# @app.route("/dashboard")
# def dashboard():
#     if "access_token" not in session:
#         flash("Lütfen giriş yapın!", "warning")
#         return redirect(url_for("login"))

#     headers = {"Authorization": f"Bearer {session['access_token']}"}

#     response = requests.get(f"{LARAVEL_API_URL}/chart/dashboard", headers=headers)

#     if response.status_code == 200:
#         dashboard_data = response.json()
#         return render_template("dashboard.html", data=dashboard_data)

#     flash("Yetkisiz erişim, tekrar giriş yapın!", "danger")
#     return redirect(url_for("login"))

# 🎯 Çıkış Yapma
@app.route("/logout")
def logout():
    session.clear()
    flash("Başarıyla çıkış yapıldı.", "success")
    return redirect(url_for("login"))


# # Token yenileme (Laravel API'den yeni access token al)
# @app.route("/refresh", methods=["POST"])
# def refresh_token():
#     if "refresh_token" not in session:
#         return jsonify({"error": "No refresh token"}), 401

#     response = requests.post(
#         f"{LARAVEL_API_URL}/refresh",
#         json={"refresh_token": session["refresh_token"]}
#     )

#     if response.status_code == 200:
#         new_token = response.json()["access_token"]
#         session["access_token"] = new_token
#         return jsonify({"access_token": new_token}), 200

#     return jsonify({"error": "Token refresh failed"}), 401

        
# Diger SAyfalar         
@app.route('/modem-selection', endpoint="modem_selection")
def modem_selection():
    return render_template("modem_selection.html")

@app.route('/orc-status', endpoint="orc_status")
def orc_status():
    return render_template("orc_status.html")

@app.route('/log', endpoint="log")
def log():
    return render_template("log.html")

@app.route('/alarm', endpoint="alarm")
def alarm():
    return render_template("alarm.html")    

@app.route('/equipment', endpoint="equipment")
def equipment():
    return render_template("equipments/equipments.html")


if __name__ == '__main__':
    app.run(debug=True, port=5001)