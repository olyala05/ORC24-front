from flask import Flask, render_template, request,  jsonify, redirect, url_for, session
import requests
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
LARAVEL_API_URL = "https://pierenergytrackingsystem.com/v1/orc24"

# Flask-SCSS'i başlat
Scss(app, static_dir='static', asset_dir='assets')

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/login')
def login():
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")

@app.route('/modem-selection', endpoint="modem_selection")
def modem_selection():
    return render_template("modem_selection.html")


@app.route('/orc-status', endpoint="orc_status")
def orc_status():
    return render_template("orc_status.html")

# # Kullanıcı giriş yaparsa, Laravel API'den token alacağız
# @app.route("/login", methods=["GET"])  
# def login():
#     email = request.args.get("client_email")  
#     password = request.args.get("client_password")

#     print("Giriş Denemesi:", email, password)  

#     response = requests.get(
#         f"{LARAVEL_API_URL}/orc24/login", 
#         params={"client_email": email, "client_password": password}, 
#         headers={"Content-Type": "application/json"},
#         verify=False
#     )

#     print("Laravel API Yanıtı:", response.status_code, response.text)

#     if response.status_code == 200:
#         try:
#             api_response = response.json()
#             session["access_token"] = api_response.get("access_token")
#             return jsonify({
#                 "message": "Login successful",
#                 "access_token": api_response.get("access_token")
#             }), 200
#         except Exception as e:
#             print("JSON Decode Hatası:", e)
#             return jsonify({"error": "Invalid server response"}), 500

#     return jsonify({"error": "Invalid credentials"}), 401



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

# # Yetkilendirilmiş API isteği
# @app.route("/dashboard", methods=["GET"])
# def dashboard():
#     if "access_token" not in session:
#         return jsonify({"error": "Unauthorized"}), 401

#     headers = {"Authorization": f"Bearer {session['access_token']}"}

#     # Laravel API'den Dashboard verisi al
#     response = requests.get(f"{LARAVEL_API_URL}/chart/dashboard", headers=headers)

#     if response.status_code == 200:
#         return jsonify(response.json()), 200
#     elif response.status_code == 401:
#         # Eğer token süresi dolmuşsa, yeni token al
#         refresh_res = requests.post(
#             f"{LARAVEL_API_URL}/refresh",
#             json={"refresh_token": session["refresh_token"]}
#         )
        
#         if refresh_res.status_code == 200:
#             new_token = refresh_res.json()["access_token"]
#             session["access_token"] = new_token
#             headers["Authorization"] = f"Bearer {new_token}"

#             # Dashboard isteğini tekrar yap
#             response = requests.get(f"{LARAVEL_API_URL}/chart/dashboard", headers=headers)
#             return jsonify(response.json()), 200

#     return jsonify({"error": "Unauthorized"}), 401

# # Çıkış yap (session'ı temizle)
# @app.route("/logout", methods=["POST"])
# def logout():
#     session.clear()
#     return jsonify({"message": "Logged out"}), 200
      
         
if __name__ == '__main__':
    app.run(debug=True, port=5001)