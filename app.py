import requests
from flask import Flask, render_template, request,  jsonify, redirect, url_for, session, flash
from flask_jwt_extended import JWTManager, create_access_token
from flask_cors import CORS
from flask_scss import Scss
import json
import ipaddress
import scapy.all as scapy
import nmap
import socket
from datetime import datetime 
from requests.exceptions import RequestException  

app = Flask(__name__)
CORS(app)
app.secret_key = 'supersecretkey'
app.config["JWT_SECRET_KEY"] = "jwt_secret_key"
jwt = JWTManager(app)

# Laravel API'nin URL'si 
LARAVEL_API_URL = "https://api.pierenergytrackingsystem.com/v1/orc24"

# Ağ Arayüzü IP Aralığı (Değiştirebilirsin)
IP_RANGE = "192.168.1.0/24"

# MySQL veritabanı bağlantı bilgileri
DB_CONFIG = {"host": "localhost", "user": "root", "password": "123", "database": "iot"}

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
            f"{LARAVEL_API_URL}/login",
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

    return render_template("login.html")  

# # 🎯 Dashboard Sayfası
@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")

# 🎯 Alarm Status API'sinden veri çek
@app.route("/alarm_status", methods=["GET"])
def alarm_status():
    if "access_token" not in session:
        return jsonify({"error": "Unauthorized"}), 401 

    headers = {
        "Authorization": f"Bearer {session['access_token']}",
        "Accept": "application/json"
    }

    response = requests.get(f"{LARAVEL_API_URL}/alarm/status", headers=headers, verify=False)

    print("Alarm Status API Yanıtı:", response.status_code, response.text)

    if response.status_code == 200:
        return jsonify(response.json())
    else:
        return jsonify({"error": "Alarm status verisi alınamadı"}), response.status_code

# 🎯 1️⃣ Ağdaki Bağlı Cihazları Bulma (Sadece MAC adresi 02 veya 12 ile başlayanlar)
def get_connected_devices():
    ip_list = []

    # ARP taraması
    arp_request = scapy.ARP(pdst=IP_RANGE)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request

    try:
        answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
        if answered_list:
            for element in answered_list:
                mac_address = element[1].hwsrc
                ip_address = element[1].psrc
                
                # 🎯 Sadece 02 veya 12 ile başlayanları listele
                if mac_address.startswith("02") or mac_address.startswith("12"):
                    ip_list.append({"ip": ip_address, "mac": mac_address})

            print("Bağlı cihazlar (ARP taraması):", ip_list)
            return ip_list  

    except Exception as e:
        print(f"ARP taraması sırasında hata: {str(e)}")

    # ARP başarısız olduysa, Nmap taraması yap
    print("ARP başarısız, Nmap taraması başlatılıyor...")

    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=IP_RANGE, arguments='-sn')
        for host in nm.all_hosts():
            mac_address = nm[host]['addresses'].get('mac', None)

            # 🎯 Sadece 02 veya 12 ile başlayanları listele
            if mac_address and (mac_address.startswith("02") or mac_address.startswith("12")):
                ip_list.append({"ip": host, "mac": mac_address})

        print("Bağlı cihazlar (Nmap taraması):", ip_list)

    except Exception as e:
        print(f"Nmap taraması sırasında hata: {str(e)}")

    return ip_list  

# 🎯 2️⃣ Bağlı Cihazları Listeleme API'si
@app.route("/devices", methods=["GET"])
def list_devices():
    devices = get_connected_devices()
    return jsonify(devices)

# 🎯 3️⃣ IP Adresinin Geçerli Olduğunu Kontrol Et
def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

@app.route("/get_selected_device", methods=["GET"])
def get_selected_device():
    ip_address = session.get("selected_device_ip", None)  # Flask session'dan IP al
    return jsonify({"ip_address": ip_address})  # JSON olarak döndür

# 🎯 4️⃣ Cihaza Bağlanma
@app.route("/connect_device", methods=["POST"])
def connect_device():
    data = request.get_json()
    ip_address = data.get("ip_address")

    if not ip_address or not is_valid_ip(ip_address):
        return jsonify(success=False, error="Geçersiz IP adresi.")

    try:
        with socket.create_connection((ip_address, 80), timeout=5):
            session["selected_device_ip"] = ip_address  # 📌 Cihazı session'a kaydet
            session.permanent = True  # 📌 Session'ın kalıcı olması için
            return jsonify(success=True)
    except Exception as e:
        return jsonify(success=False, error=f"Bağlantı hatası: {str(e)}")

@app.route("/orc-status", methods=["GET", "POST"])
def orc_status():
    selected_ip = session.get("selected_device_ip")

    if not selected_ip:
        flash("Lütfen önce bir cihaz seçin!", "danger")
        return render_template("orc_status.html", error="Lütfen önce bir cihaz seçin!", modem=None, network=None)

    selected_modem = None
    network_data = None

    try:
        # 📌 Modem verilerini al
        url_modem = f"http://{selected_ip}:8085/get_modems"
        print("Modem URL:", url_modem)  # 🔍 Konsola yazdır
        try:
            response_modem = requests.get(url_modem, timeout=5)  # 5 saniye timeout ekledik
            response_modem.raise_for_status()
            modems = response_modem.json().get("modems", [])
            selected_modem = modems[0] if modems else None
        except requests.exceptions.RequestException as e:
            print(f"⚠️ Modem bilgisi alınamadı: {e}")  # Hata logla ama hata döndürme!
            flash(f"Modem bilgisi alınamadı: {e}", "warning")

        # 📌 Ağ bilgilerini al
        url_network = f"http://{selected_ip}:8085/check_network"
        print("Ağ URL:", url_network)  # 🔍 Konsola yazdır
        try:
            response_network = requests.get(url_network, timeout=5)  # 5 saniye timeout ekledik
            response_network.raise_for_status()
            network_data = response_network.json()
            print("Wi-Fi SSID:", network_data.get("connected_ssid"))  # 🔍 Konsola yazdır
        except requests.exceptions.RequestException as e:
            print(f"⚠️ Ağ bilgisi alınamadı: {e}")  # Hata logla ama hata döndürme!
            flash(f"Ağ bilgisi alınamadı: {e}", "warning")

        # 📌 Tarih formatını dönüştür
        if selected_modem and "created_at" in selected_modem:
            raw_date = selected_modem["created_at"]
            try:
                parsed_date = datetime.strptime(raw_date, "%a, %d %b %Y %H:%M:%S %Z")
                selected_modem["created_at"] = parsed_date.strftime("%Y-%m-%d %H:%M:%S")
            except ValueError:
                selected_modem["created_at"] = "Geçersiz Tarih"

        return render_template("orc_status.html", modem=selected_modem, network=network_data, error=None)

    except Exception as e:
        print("🔥 Genel hata:", e)
        return render_template("orc_status.html", error=f"Beklenmeyen hata: {e}", modem=None, network=None)


# Diger SAyfalar         
@app.route('/modem-selection', endpoint="modem_selection")
def modem_selection():
    return render_template("modem_selection.html")

@app.route('/log', endpoint="log")
def log():
    return render_template("log.html")

@app.route('/alarm', endpoint="alarm")
def alarm():
    return render_template("alarm.html")    

@app.route('/equipment', endpoint="equipment")
def equipment():
    return render_template("equipments/equipments.html")

# 🎯 Çıkış Yapma
@app.route("/logout")
def logout():
    session.clear()
    flash("Başarıyla çıkış yapıldı.", "success")
    return redirect(url_for("login"))

if __name__ == '__main__':
    app.run(debug=True, port=5004)