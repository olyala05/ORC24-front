import requests
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
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
import logging
import re
import subprocess   
import platform
import os

app = Flask(__name__)
CORS(app)
app.secret_key = 'supersecretkey'
app.config["JWT_SECRET_KEY"] = "jwt_secret_key"
jwt = JWTManager(app)

# Flask logları ayarla
logging.basicConfig(level=logging.INFO)  # INFO seviyesinde log al
logger = logging.getLogger(__name__)

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

        response = requests.get(
            f"{LARAVEL_API_URL}/login",
            params={"client_email": email, "client_password": password},
            headers={"Accept": "application/json"},
            verify=False
        )

        if response.status_code == 200:
            try:
                api_response = response.json()
                session["access_token"] = api_response.get("access_token")

                # 🎯 Başarılı giriş bilgisini session içinde sakla
                session["login_success"] = True

                return redirect(url_for("dashboard"))  # 🎯 Dashboard sayfasına yönlendir
            except Exception as e:
                flash("Sunucudan geçersiz yanıt alındı!", "danger")
                return redirect(url_for("login"))

        flash("Hatalı e-posta veya şifre!", "danger")
        return redirect(url_for("login"))
    login_success = session.pop("login_success", None)
    return render_template("login.html", login_success=login_success)

# 🎯 Dashboard Sayfası
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

def raspberry_pi_nmap_scan():
    """ Raspberry Pi'de 'nmap -sn' komutunu çalıştırarak bağlı cihazları listeler """
    try:
        output = subprocess.check_output(["sudo", "nmap", "-sn", "192.168.1.0/24"], universal_newlines=True)
        matches = re.findall(r"(\d+\.\d+\.\d+\.\d+)|(([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2})", output)
        
        macs = [m[1] for m in matches[1::2]]
        ips = [m[0] for m in matches[0::2]]
        mac_ip_map = dict(zip(macs, ips))
        
        filtered_devices = [(mac, mac_ip_map[mac]) for mac in mac_ip_map if (mac.startswith("02") or mac.startswith("12"))]
        return filtered_devices

    except subprocess.CalledProcessError as e:
        return ResponseHandler.error(message="Nmap taraması sırasında bir hata oluştu.", code=500, details=str(e))

@app.route("/devices", methods=["GET"])
def list_devices():
    try:
        devices = raspberry_pi_nmap_scan()
        formatted_devices = [{"mac": mac, "ip": ip} for mac, ip in devices]
        return ResponseHandler.success(message="Devices retrieved successfully", data=formatted_devices)
    except Exception as e:
        return ResponseHandler.error(message="Failed to retrieve devices", code=500, details=str(e))

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

@app.route("/get_selected_device", methods=["GET"])
def get_selected_device():
    ip_address = session.get("selected_device_ip", None)  
    return jsonify({"ip_address": ip_address})  

# Cihaza Bağlanma
@app.route("/connect_device", methods=["POST"])
def connect_device():
    data = request.get_json()
    ip_address = data.get("ip_address")

    if not ip_address or not is_valid_ip(ip_address):
        return jsonify(success=False, error="Geçersiz IP adresi.")

    try:
        with socket.create_connection((ip_address, 80), timeout=5):
            session["selected_device_ip"] = ip_address 
            session.permanent = True 
            return jsonify(success=True)
    except Exception as e:
        return jsonify(success=False, error=f"Bağlantı hatası: {str(e)}")


#  ORC Stataus
@app.route("/orc-status", methods=["GET", "POST"])
def orc_status():
    selected_ip = session.get("selected_device_ip")

    if not selected_ip:
        flash("Lütfen önce bir cihaz seçin!", "danger")
        return render_template("orc_status.html", error="Lütfen önce bir cihaz seçin!", modem=None, network=None)

    selected_modem = None
    network_data = None

    try:
        # Modem verilerini al
        url_modem = f"http://{selected_ip}:8085/get_modems"
        print("Modem URL:", url_modem)  # 🔍 Konsola yazdır
        response_modem = requests.get(url_modem, timeout=5)  # 5 saniye timeout ekledik
        response_modem.raise_for_status()
        modems = response_modem.json().get("data", [])
        selected_modem = modems[0] if modems else None

        url_network = f"http://{selected_ip}:8085/check_network"
        print("Ağ URL:", url_network)
        try:
            response_network = requests.get(url_network, timeout=5)
            response_network.raise_for_status()
            network_full = response_network.json()
            # Yalnızca 'data' kısmını al
            network_data = network_full.get("data", {})
            print("Wi-Fi SSID:", network_data.get("connected_ssid"))
        except requests.exceptions.RequestException as e:
            print(f"⚠️ Ağ bilgisi alınamadı: {e}")
            flash(f"Ağ bilgisi alınamadı: {e}", "warning")

        # Tarih formatını dönüştür
        if selected_modem and "created_at" in selected_modem:
            raw_date = selected_modem["created_at"]
            try:
                parsed_date = datetime.strptime(raw_date, "%a, %d %b %Y %H:%M:%S %Z")
                selected_modem["created_at"] = parsed_date.strftime("%Y-%m-%d %H:%M:%S")
            except ValueError:
                selected_modem["created_at"] = "Geçersiz Tarih"

        return render_template("orc_status.html", modem=selected_modem, network=network_data, error=None)

    except Exception as e:
        print("Genel hata:", e)
        return render_template("orc_status.html", error=f"Beklenmeyen hata: {e}", modem=None, network=None)


# Equipments Modbus
@app.route("/modbus_request", methods=["POST"])
def modbus_request():
    """
    Seçili cihazdan Modbus verilerini alır ve frontend'e iletir.
    """
    selected_ip = session.get("selected_device_ip")  
    if not selected_ip:
        logger.warning("Cihaz seçilmedi!")
        return jsonify({"error": "Cihaz seçilmedi. Lütfen önce bir cihaz bağlayın."}), 400

    try:
        logger.info(f"Modbus verisi alınıyor: {selected_ip}") 

        # HTTP ile cihazdan Modbus verilerini al
        url = f"http://{selected_ip}:8085/get_modbus_data"
        response = requests.get(url, timeout=500)  
        response.raise_for_status()

        modbus_data = response.json().get("modbus_data", [])
        if not modbus_data:
            logger.warning("Modbus verisi bulunamadı.")
            return jsonify({"error": "Modbus verisi alınamadı veya cihaz desteklemiyor."}), 500

        logger.info(
            f"Modbus verisi başarıyla alındı: {len(modbus_data)} cihaz bulundu.")  
        return jsonify({"modbus_data": modbus_data})

    except requests.exceptions.RequestException as e:
        logger.error(f"Modbus isteği hatası: {e}")
        return jsonify({"error": f"Modbus bağlantı hatası: {str(e)}"}), 500


@app.route("/disconnect_request", methods=["POST"])
def disconnect_request():
    """
    Seçili cihazın Wi-Fi bağlantısını keser.
    """
    selected_ip = session.get("selected_device_ip")  # Seçili cihazın IP'sini al

    if not selected_ip:
        logger.warning("Cihaz seçilmedi!")
        return jsonify({"error": "Cihaz seçilmedi. Lütfen önce bir cihaz bağlayın."}), 400

    try:
        logger.info(f"🔌 Wi-Fi bağlantısı kesiliyor: {selected_ip}")

        # HTTP ile cihazdan Wi-Fi'yi kapatmasını iste
        url = f"http://{selected_ip}:8085/disconnect_wifi"
        response = requests.post(url, timeout=10)  # Timeout ekleyelim
        response.raise_for_status()

        logger.info("Wi-Fi başarıyla kapatıldı.")
        return jsonify({"status": "success", "message": "Wi-Fi bağlantısı kapatıldı."})

    except requests.exceptions.RequestException as e:
        logger.error(f"Wi-Fi kapatma hatası: {e}")
        return jsonify({"error": f"Wi-Fi bağlantısı kapatılamadı: {str(e)}"}), 500


@app.route("/equipments-with-models", methods=["POST"])
def equipments_with_models():
    data = request.json
    ip_address = data.get("ip_address")

    if not ip_address:
        return jsonify({"error": "IP adresi belirtilmedi"}), 400

    try:
        url = f"http://{ip_address}:8085/get_equipments_with_models"
        response = requests.get(url, timeout=200)
        response.raise_for_status()

        equipment_data = response.json()

        if "warning" in equipment_data:
            return jsonify({"warning": equipment_data["warning"]}), 200

        session["equipment_data"] = equipment_data
        return jsonify(equipment_data)

    except requests.exceptions.RequestException as e:
        logging.error(f"🔥 Equipment isteği hatası: {e}")
        return jsonify({"error": f"Equipment Boş"})


@app.route('/equipment', endpoint="equipment")
def equipment():
    return render_template("equipments/equipments.html")


@app.route("/equipment-setting", methods=["GET"])
def equipment_setting():
    """
    Equipment sayfasını render eder ve cihaz modellerini gösterir.
    """
    modbus_data = session.get("modbus_data", [])  # Modbus verilerini al
    return render_template("equipments/equipment_setting.html", modbus_data=modbus_data)


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

@app.route('/switch', endpoint="switch")
def switch():
    return render_template("test/switch.html")

@app.route('/test', endpoint="test")
def test():
    return render_template("test/test.html")


@app.route('/equipment-details', endpoint="equipment_detatils")
def equipment_details():
    return render_template("equipments/equipment_details.html")


# !! Settings Start
@app.route('/settings', endpoint="settings")
def settings():
    return render_template("settings/setting.html")


@app.route('/orc-settings', endpoint="orc_settings")
def orc_setting():
    return render_template("settings/orc_set.html")


@app.route('/osos-settings', endpoint="osos_settings")
def osos_setting():
    return render_template("settings/osos_set.html")


@app.route('/equipment-settings', endpoint="equipment_settings")
def equipment_setting():
    return render_template("settings/equipment_set.html")
# !! Settings End

# !! Data Start 
@app.route('/data', endpoint="data")
def data():
    return render_template("datas/data.html")

#Live Data 
@app.route('/live-data', endpoint="live-data")
def live_data():
    return render_template("datas/live_data.html")

@app.route('/live-data-detail', endpoint="live-data-detail")
def live_data_detail():
    return render_template("datas/live_data_detail.html")

# Hourly Data   
@app.route('/hourly-data', endpoint="hourly-data")
def hourly_data():
    return render_template("datas/hourly_data.html")

@app.route('/hourly-data-detail', endpoint="hourly-data-detail")
def hourly_data_detail():
    return render_template("datas/hourly_data_detail.html")

# Daily Data    
@app.route('/daily-data', endpoint="daily-data")
def daily_data():
    return render_template("datas/daily_data.html")

@app.route('/daily-data-detail', endpoint="daily-data-detail")
def daily_data_detail():
    return render_template("datas/daily_data_detail.html")
# !! Data End

@app.route("/logout", methods=["POST"])
def logout():
    session.clear() 
    return redirect(url_for("login")) 

class ResponseHandler:
    @staticmethod
    def success(message=None, data=None):
        response = {
            "status": "success",
            "message": message,
            "data": data
        }
        return jsonify(response), 200

    @staticmethod
    def error(message="An error occurred", code=500, details=None):
        response = {
            "status": "error",
            "message": message,
            "error": {
                "code": code,
                "details": details
            }
        }
        return jsonify(response), code

if __name__ == '__main__':
    app.run(debug=True, port=5000)
