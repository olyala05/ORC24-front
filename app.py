import requests
from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    redirect,
    url_for,
    session,
    flash,
)
from flask_jwt_extended import JWTManager, create_access_token
from flask_cors import CORS
from flask_scss import Scss
import json
import ipaddress
import scapy.all as scapy
import nmap
import socket
from datetime import datetime
import logging
import pymodbus.client.tcp 

app = Flask(__name__)
CORS(app)
app.secret_key = "supersecretkey"
app.config["JWT_SECRET_KEY"] = "jwt_secret_key"
jwt = JWTManager(app)

# Flask logları ayarla
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Laravel API'nin URL'si
LARAVEL_API_URL = "https://api.pierenergytrackingsystem.com/v1/orc24"

# Ağ Arayüzü IP Aralığı (Değiştirebilirsin)
IP_RANGE = "192.168.1.0/24"

# MySQL veritabanı bağlantı bilgileri
DB_CONFIG = {"host": "localhost", "user": "root", "password": "123", "database": "iot"}

# Flask-SCSS'i başlat
Scss(app, static_dir="static", asset_dir="assets")

last_connection_time = None

@app.route("/")
def index():
    return render_template("index.html")


# Giriş Sayfası
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        response = requests.get(
            f"{LARAVEL_API_URL}/login",
            params={"client_email": email, "client_password": password},
            headers={"Accept": "application/json"},
            verify=False,
        )

        if response.status_code == 200:
            try:
                api_response = response.json()
                session["access_token"] = api_response.get("access_token")
                session["login_success"] = True
                return redirect(url_for("dashboard")) 
            except Exception as e:
                flash("Sunucudan geçersiz yanıt alındı!", "danger")
                return redirect(url_for("login"))

        flash("Hatalı e-posta veya şifre!", "danger")
        return redirect(url_for("login"))
    login_success = session.pop("login_success", None)
    return render_template("login.html", login_success=login_success)

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html", page_title="Dashboard")


# Alarm Status API'sinden veri çek
@app.route("/alarm_status", methods=["GET"])
def alarm_status():
    if "access_token" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    headers = {
        "Authorization": f"Bearer {session['access_token']}",
        "Accept": "application/json",
    }

    response = requests.get(
        f"{LARAVEL_API_URL}/alarm/status", headers=headers, verify=False
    )

    print("Alarm Status API Yanıtı:", response.status_code, response.text)

    if response.status_code == 200:
        return jsonify(response.json())
    else:
        return jsonify({"error": "Alarm status verisi alınamadı"}), response.status_code


def arp_scan(ip_range):
    """Belirtilen IP aralığında ARP taraması yaparak 02 veya 12 ile başlayan MAC adreslerini bulur"""
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    ip_list = []
    for element in answered_list:
        mac_address = element[1].hwsrc
        if mac_address.startswith("02") or mac_address.startswith("12"):
            ip_list.append({"ip": element[1].psrc, "mac": mac_address})

    return ip_list


def nmap_scan(ip_range):
    """Belirtilen IP aralığında Nmap taraması yaparak 02 veya 12 ile başlayan MAC adreslerini bulur"""
    nm = nmap.PortScanner()
    nm.scan(hosts=ip_range, arguments="-sn")

    ip_list = []
    for host in nm.all_hosts():
        mac_address = nm[host]["addresses"].get("mac", "")
        if mac_address.startswith("02") or mac_address.startswith("12"):
            ip_list.append({"ip": host, "mac": mac_address})

    return ip_list


def get_connected_devices():
    """Önce ARP taraması, başarısız olursa Nmap taraması ile cihazları bulur"""
    print("ARP taraması başlatılıyor...")
    devices = arp_scan(IP_RANGE)

    if not devices:
        print("ARP taraması başarısız, Nmap taraması başlatılıyor...")
        devices = nmap_scan(IP_RANGE)

    print("Bağlı cihazlar:", devices)
    return devices


# Bağlı Cihazları Listeleme API'si
@app.route("/devices", methods=["GET"])
def list_devices():
    devices = get_connected_devices()
    return jsonify(devices)


# IP Adresinin Geçerli Olduğunu Kontrol Et
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
            session["selected_device_ip"] = ip_address  # 📌 Cihazı session'a kaydet
            session.permanent = True  # 📌 Session'ın kalıcı olması için
            return jsonify(success=True)
    except Exception as e:
        return jsonify(success=False, error=f"Bağlantı hatası: {str(e)}")


# ORC Status
@app.route("/orc-status", methods=["GET", "POST"], endpoint="orc_status")
def orc_status():
    selected_ip = session.get("selected_device_ip")

    if not selected_ip:
        flash("Lütfen önce bir cihaz seçin!", "danger")
        return render_template(
            "orc_status/orc_status.html",
            page_title="ORC Status",
            error="Lütfen önce bir cihaz seçin!",
            modem=None,
            network=None,
        )

    selected_modem = None
    network_data = None

    try:
        # Modem bilgilerini al
        url_modem = f"http://{selected_ip}:8085/get_modems"
        response_modem = requests.get(url_modem, timeout=5)
        response_modem.raise_for_status()
        modems = response_modem.json().get("data", [])

        if modems:
            selected_modem = modems[0]
            if "created_at" in selected_modem and selected_modem["created_at"]:
                try:
                    created_at_dt = datetime.strptime(
                        selected_modem["created_at"], "%a, %d %b %Y %H:%M:%S %Z"
                    )
                    selected_modem["created_at"] = created_at_dt.strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                except ValueError:
                    selected_modem["created_at"] = "Tarih formatı hatalı"

        # Ağ bilgilerini al
        url_network = f"http://{selected_ip}:8085/check_network"
        try:
            response_network = requests.get(url_network, timeout=5)
            response_network.raise_for_status()
            network_full = response_network.json()
            network_data = network_full.get("data", {})

            # Aktif bağlantıları belirleme
            active_connections = []
            if network_data.get("wifi_connected"):
                active_connections.append("Wi-Fi")
            if network_data.get("ethernet_connected"):
                active_connections.append("Ethernet")
            if network_data.get("vpn_connected"):
                active_connections.append("VPN")

            network_data["active_connections"] = active_connections
            network_data["network_type_list"] = active_connections

        except requests.exceptions.RequestException as e:
            flash(f"Ağ bilgisi alınamadı: {e}", "warning")

        return render_template(
            "orc_status/orc_status.html",
            page_title="ORC Status",
            modem=selected_modem,
            network=network_data,
            error=None,
        )

    except Exception as e:
        return render_template(
            "orc_status/orc_status.html",
            page_title="ORC Status",
            error=f"Beklenmeyen hata: {e}",
            modem=None,
            network=None,
        )


@app.route("/get_modem_info", methods=["GET"])
def get_modem_info():
    selected_ip = session.get("selected_device_ip")

    if not selected_ip:
        return ResponseHandler.error(
            message="Device IP missing",
            code=400,
            details="Selected device IP is required",
        )

    try:
        # Fetch modem data from the device
        url_modem = f"http://{selected_ip}:8085/get_modems"
        response = requests.get(url_modem, timeout=5)
        response.raise_for_status()
        modems = response.json().get("data", [])

        if not modems:
            return ResponseHandler.error(
                message="No modem data found", code=404, details="Modem list is empty"
            )

        # Get the first modem (assuming only one is active)
        modem = modems[0]

        # Extract required fields
        modem_info = {
            "name": modem.get("name", "Unknown"),
            "status": "Active" if modem.get("status") == 1 else "Inactive",
        }

        return ResponseHandler.success(
            message="Modem info retrieved successfully", data=modem_info
        )

    except requests.RequestException as e:
        return ResponseHandler.error(
            message="Failed to fetch modem data", code=500, details=str(e)
        )
    except Exception as e:
        return ResponseHandler.error(
            message="Unexpected error occurred", code=500, details=str(e)
        )


# network info
@app.route("/wi-fi-list", methods=["POST"])
def wi_fi_list():
    selected_ip = session.get("selected_device_ip")

    if not selected_ip:
        print("ERROR: No selected device IP found!")
        return jsonify({"error": "IP address is missing"}), 400

    try:
        print(f"📡 Wi-Fi listesi için cihazdan veri alınıyor: {selected_ip}")
        url = f"http://{selected_ip}:8085/check_network"
        response = requests.get(url)
        print(f"Cihazdan cevap alındı: {response.status_code}")

        response.raise_for_status()  # Hata fırlatırsa yakalayalım
        network_data = response.json()
        print(f"📡 Gelen JSON: {network_data}")

        return jsonify(
            {
                "status": "success",
                "message": "Connection information retrieved successfully.",
                "data": network_data["data"],
            }
        )
    except requests.RequestException as e:
        print(f"ERROR: Request failed - {str(e)}")
        return (
            jsonify(
                {
                    "status": "error",
                    "message": f"Failed to connect to device: {str(e)}",
                    "data": None,
                }
            ),
            500,
        )


@app.route("/connect_wifi", methods=["POST"])
def connect_wifi():
    try:
        data = request.json
        print("Gelen JSON:", data)
        ssid = data.get("ssid")
        password = data.get("password")
        selected_ip = session.get("selected_device_ip")

        if not ssid:
            return ResponseHandler.error(
                message="SSID not found", code=400, details="SSID is required"
            )

        if not selected_ip:
            return ResponseHandler.error(
                message="Device IP missing",
                code=400,
                details="Selected device IP is required",
            )

        url = f"http://{selected_ip}:8085/connect_wifi"
        response = requests.post(url, json={"ssid": ssid, "password": password})
        response.raise_for_status()
        result = response.json()

        if result.get("status") == "success":
            return ResponseHandler.success(
                message="Connection established successfully."
            )

        return ResponseHandler.error(
            message=result.get("message", "Connection failed"),
            code=400,
            details="Wi-Fi connection issue",
        )

    except requests.RequestException as e:
        return ResponseHandler.error(message="Network error", code=500, details=str(e))
    except Exception as e:
        return ResponseHandler.error(
            message="Unexpected error occurred", code=500, details=str(e)
        )


@app.route("/disconnect_wifi", methods=["POST"])
def disconnect_wifi():
    try:
        selected_ip = session.get("selected_device_ip")

        if not selected_ip:
            return ResponseHandler.error(
                message="Device IP missing",
                code=400,
                details="Selected device IP is required",
            )

        # Cihaza bağlantıyı kesme isteği gönder
        url = f"http://{selected_ip}:8085/disconnect_wifi"
        response = requests.post(url)
        response.raise_for_status()
        result = response.json()

        if result.get("status") == "success":
            return ResponseHandler.success(
                message="Wi-Fi connection successfully disconnected."
            )

        return ResponseHandler.error(
            message=result.get("message", "Disconnection failed"),
            code=400,
            details="Wi-Fi disconnection issue",
        )

    except requests.RequestException as e:
        return ResponseHandler.error(message="Network error", code=500, details=str(e))
    except Exception as e:
        return ResponseHandler.error(
            message="Unexpected error occurred", code=500, details=str(e)
        )

#Cloud Status
@app.route("/cloud-status", methods=["POST"])
def cloud_status():
    global last_cloud_connection_time
    try:
        response = requests.get("https://pierenergytrackingsystem.com/v1/login", timeout=5)
        
        if response.status_code == 200:
            last_cloud_connection_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            return ResponseHandler.success(
                message="Cloud connection successful",
                data={
                    "cloud_connected": True,
                    "last_connection_time": last_cloud_connection_time,
                },
            )
        return ResponseHandler.error(message="Cloud connection failed", code=response.status_code)

    except requests.RequestException:
        return ResponseHandler.error(message="Cloud connection failed", code=500)

# RabbitMQ Status
@app.route("/rabbitmq-status", methods=["POST"])
def rabbitmq_status():
    global last_connection_time
    selected_ip = session.get("selected_device_ip")

    if not selected_ip:
        return ResponseHandler.error(
            message="Device IP missing",
            code=400,
            details="Selected device IP is required",
        )
    try:
        url = f"http://{selected_ip}:8085/check_rabbitmq"
        response = requests.get(url, timeout=5)  
        response.raise_for_status()
        rabbitmq_status = response.json()

        if rabbitmq_status["data"]["rabbitmq_connected"]:
            last_connection_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        return ResponseHandler.success(
            message="RabbitMQ status retrieved successfully",
            data={
                "rabbitmq_connected": rabbitmq_status["data"]["rabbitmq_connected"],
                "last_connection_time": last_connection_time
            },
        )
    except requests.RequestException as e:
        return ResponseHandler.error(
            message="Failed to fetch RabbitMQ status",
            code=500,
            details=str(e),
            data={
                "rabbitmq_connected": False,
                "last_connection_time": last_connection_time
            }
        )
        
@app.route("/vpn-status", methods=["POST"])
def vpn_status():
    selected_ip = session.get("selected_device_ip")

    if not selected_ip:
        return ResponseHandler.error(
            message="Device IP missing",
            code=400,
            details="Selected device IP is required",
        )

    try:
        url = f"http://{selected_ip}:8085/check_vpn"
        response = requests.get(url)
        response.raise_for_status()
        vpn_data = response.json()

        return ResponseHandler.success(
            message="VPN status retrieved successfully",
            data={"vpn_connected": vpn_data["data"]["vpn_connected"]},
        )

    except requests.RequestException as e:
        return ResponseHandler.error(
            message="Failed to fetch VPN status", code=500, details=str(e)
        )


@app.route("/fetch_equipment_details", methods=["GET"])
def fetch_equipment_details():
    selected_ip = session.get("selected_device_ip")
    equipment_id = session.get("selected_equipment_id")

    if not selected_ip:
        return jsonify({"error": "Cihaz seçilmedi. Lütfen önce bir cihaz seçin!"}), 400
    if not equipment_id:
        return (
            jsonify({"error": "Ekipman seçilmedi. Lütfen önce bir ekipman seçin!"}),
            400,
        )

    print(f"Backend'e Gelen Equipment ID: {equipment_id}")

    try:
        url = f"http://{selected_ip}:8085/get_equipment_details/{equipment_id}"
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        equipment_data = response.json()

        return jsonify(equipment_data)
    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Modbus bağlantı hatası: {str(e)}"}), 500


@app.route("/set_selected_equipment", methods=["POST"])
def set_selected_equipment():
    data = request.get_json()
    equipment_id = data.get("equipment_id")
    if not equipment_id:
        return jsonify({"error": "Ekipman ID'si belirtilmedi!"}), 400
    session["selected_equipment_id"] = equipment_id
    session.modified = True
    return jsonify({"success": True, "message": "Ekipman seçildi!"})

# Equipments Modbus
@app.route("/modbus_request", methods=["POST"])
def modbus_request():
    selected_ip = session.get("selected_device_ip")
    if not selected_ip:
        logger.warning("Cihaz seçilmedi!")
        return (
            jsonify({"error": "Cihaz seçilmedi. Lütfen önce bir cihaz bağlayın."}),
            400,
        )
    try:
        logger.info(f"Modbus verisi alınıyor: {selected_ip}")
        url = f"http://{selected_ip}:8085/get_modbus_data"
        response = requests.get(url, timeout=500)
        response.raise_for_status()

        modbus_data = response.json().get("modbus_data", [])
        if not modbus_data:
            logger.warning("Modbus verisi bulunamadı.")
            return (
                jsonify({"error": "Modbus verisi alınamadı veya cihaz desteklemiyor."}),
                500,
            )

        logger.info(
            f"Modbus verisi başarıyla alındı: {len(modbus_data)} cihaz bulundu."
        )
        return jsonify({"modbus_data": modbus_data})

    except requests.exceptions.RequestException as e:
        logger.error(f"Modbus isteği hatası: {e}")
        return jsonify({"error": f"Modbus bağlantı hatası: {str(e)}"}), 500


# Read Modbus
@app.route("/validate_modbus", methods=["POST"])
def validate_modbus():
    selected_ip = session.get("selected_device_ip")
    if not selected_ip:
        return ResponseHandler.error(
            message="Device IP missing",
            code=400,
            details="Selected device IP is required",
        )

    data = request.json
    if not data:
        return ResponseHandler.error(message="No JSON data received", code=400)

    modbus_params = data.get("modbus_params")
    if not modbus_params:
        return ResponseHandler.error(message="Modbus parameters missing", code=400)

    try:
        url = f"http://{selected_ip}:8085/modbus_config"
        response = requests.post(url, json=modbus_params)
        response.raise_for_status()
        return ResponseHandler.success(
            message="Command sent to ORC24 successfully", data=response.json()
        )
    except requests.RequestException as e:
        return ResponseHandler.error(
            message="Failed to send command to ORC24", code=500, details=str(e)
        )


@app.route("/modbus_test", methods=["POST", "GET"])
def modbus_test():
    """Check if the selected device has a valid Modbus connection."""
    selected_ip = session.get("selected_device_ip")

    if not selected_ip:
        return ResponseHandler.error(
            message="Device IP missing",
            code=400,
            details="Selected device IP is required",
        )

    try:
        url = f"http://{selected_ip}:8085/modbus_test"
        response = requests.get(url)
        response.raise_for_status()

        result = response.json()  # JSON verisini bir değişkene al

        if result.get("status") == "success":
            return ResponseHandler.success(
                message="Modbus test successful", data=result.get("data", [])
            )

        # Eğer `status` "success" değilse, hata mesajını API'den al ve kullanıcıya döndür
        return ResponseHandler.error(
            message="Modbus test failed",
            code=400,
            details=result.get("message", "No valid Modbus response"),
        )

    except requests.RequestException as e:
        return ResponseHandler.error(
            message="Device connection error",
            code=500,
            details=f"Failed to connect to {selected_ip}: {str(e)}",
        )

    except Exception as e:
        return ResponseHandler.error(
            message="Unexpected error occurred", code=500, details=str(e)
        )


@app.route("/disconnect_request", methods=["POST"])
def disconnect_request():
    selected_ip = session.get("selected_device_ip")  

    if not selected_ip:
        logger.warning("Cihaz seçilmedi!")
        return (
            jsonify({"error": "Cihaz seçilmedi. Lütfen önce bir cihaz bağlayın."}),
            400,)
    try:
        logger.info(f"Wi-Fi bağlantısı kesiliyor: {selected_ip}")
        url = f"http://{selected_ip}:8085/disconnect_wifi"
        response = requests.post(url, timeout=10)
        response.raise_for_status()
        logger.info("Wi-Fi başarıyla kapatıldı.")
        return jsonify({"status": "success", "message": "Wi-Fi bağlantısı kapatıldı."})

    except requests.exceptions.RequestException as e:
        logger.error(f"Wi-Fi kapatma hatası: {e}")
        return jsonify({"error": f"Wi-Fi bağlantısı kapatılamadı: {str(e)}"}), 500


@app.route("/equipments-with-models", methods=["POST"])
def equipments_with_models():
    
    selected_ip = session.get("selected_device_ip")

    if not selected_ip:
        return jsonify({"error": "IP adresi belirtilmedi"}), 400
    try:
        url = f"http://{selected_ip}:8085/get_equipments_with_models"
        response = requests.get(url, timeout=200)
        response.raise_for_status()
        equipment_data = response.json()

        if "warning" in equipment_data:
            return jsonify({"warning": equipment_data["warning"]}), 200
        session["equipment_data"] = equipment_data
        return jsonify(equipment_data)
    except requests.exceptions.RequestException as e:
        logging.error(f"Equipment isteği hatası: {e}")
        return jsonify({"error": f"Equipment Boş"})


@app.route("/equipment", endpoint="equipment")
def equipment():
    return render_template("equipments/equipments.html", page_title="Equipments")


@app.route("/equipment-setting", methods=["GET"])
def equipment_setting():
    modbus_data = session.get("modbus_data", [])
    return render_template(
        "equipments/equipment_setting.html",
        modbus_data=modbus_data,
        page_title="Equipment Setting",
    )

# Diger Sayfalar
@app.route("/modem-selection", endpoint="modem_selection")
def modem_selection():
    return render_template("modem_selection.html", page_title="Modem Selection")

@app.route("/switch", endpoint="switch")
def switch():
    return render_template("test/switch.html", page_title="Switch")


@app.route("/test", endpoint="test")
def test():
    return render_template("test/test.html", page_title="Test")


@app.route("/equipment-details", endpoint="equipment_details")
def equipment_details():
    return render_template(
        "equipments/equipment_details.html", page_title="Equipments Details"
    )


# !! Settings Start
@app.route("/settings", endpoint="settings")
def settings():
    return render_template("settings/setting.html", page_title="Settings")


@app.route("/orc-settings", endpoint="orc_settings")
def orc_setting():
    return render_template("settings/orc_set.html", page_title="Orc Settings")


@app.route("/osos-settings", endpoint="osos_settings")
def osos_setting():
    return render_template("settings/osos_set.html", pgae_title="Osos Settings")

@app.route("/equipment-settings", endpoint="equipment_settings")
def equipment_setting():
    return render_template(
        "settings/equipment_set.html", page_title="Equipment Settings"
    )
# !! Settings End

# !! Test Start
@app.route("/send_command", methods=["POST"])
def send_command():
    selected_ip = session.get("selected_device_ip")

    if not selected_ip:
        return ResponseHandler.error(
            message="Device IP missing",
            code=400,
            details="Selected device IP is required",
        )

    data = request.json
    command = data.get("command")

    if not command:
        return ResponseHandler.error(
            message="Command missing", code=400, details="Command is required"
        )
    try:
        url = f"http://{selected_ip}:8085/execute_command"
        response = requests.post(url, json={"command": command})
        response.raise_for_status()
        return ResponseHandler.success(
            message="Command sent to ORC24 successfully", data=response.json()
        )
    except requests.RequestException as e:
        return ResponseHandler.error(
            message="Failed to send command to ORC24", code=500, details=str(e)
        )
# !! Test End

# !! Data Start
@app.route("/data", endpoint="data")
def data():
    return render_template("datas/data.html", page_title="Datas")

# Live Data
@app.route("/live-data", endpoint="live-data")
def live_data():
    return render_template("datas/live_data.html", page_title="Live Data")

# Live Data
@app.route("/fetch_grouped_live_data", methods=["POST"])
def fetch_grouped_live_data():
    selected_ip = session.get("selected_device_ip")
    if not selected_ip:
        return jsonify({"error": "Lütfen önce bir cihaz seçin!"}), 400

    try:
        url = f"http://{selected_ip}:8085/get_grouped_live_data"
        response = requests.get(url)
        response.raise_for_status()
        live_data = response.json().get("data", [])

        return (
            jsonify({"equipments": live_data})
            if live_data
            else jsonify({"message": "Bu tablo boş"})
        ), 404

    except requests.RequestException as e:
        return jsonify({"error": str(e)}), 500

@app.route("/fetch_live_data_paginated", methods=["POST"])
def fetch_live_data_paginated():
    """
    Sayfalama ile canlı veri döndüren endpoint.
    """
    selected_ip = session.get("selected_device_ip")  # Seçili cihazın IP adresi
    data = request.json
    page = int(data.get("page", 1))
    per_page = int(data.get("per_page", 20))

    if not selected_ip:
        return jsonify({"error": "Lütfen önce bir cihaz seçin!"}), 400

    print(f"📡 IP: {selected_ip}, Sayfa: {page}, Veri Sayısı: {per_page}")

    try:
        # IP adresine göre cihazdan veri al
        url = f"http://{selected_ip}:8085/get_live_data?page={page}&per_page={per_page}"
        response = requests.get(url)
        response.raise_for_status()
        live_data = response.json()

        return jsonify(live_data)
    except requests.RequestException as e:
        return jsonify({"error": str(e)}), 500

@app.route("/live-data-detail", endpoint="live-data-detail")
def live_data_detail():
    return render_template("datas/live_data_detail.html", page_title="Live Data Detail")

# Hourly Data
@app.route("/hourly-data", endpoint="hourly-data")
def hourly_data():
    return render_template("datas/hourly_data.html", page_title="Hourly Data")

@app.route("/fetch_grouped_hourly_data", methods=["POST"])
def fetch_grouped_hourly_data():
    selected_ip = session.get("selected_device_ip")
    if not selected_ip:
        return jsonify({"error": "Lütfen önce bir cihaz seçin!"}), 400

    try:
        url = f"http://{selected_ip}:8085/get_grouped_hourly_data"
        response = requests.get(url)
        response.raise_for_status()
        hourly_data = response.json().get("data", [])

        return (
            jsonify({"equipments": hourly_data})
            if hourly_data
            else jsonify({"message": "Bu tablo boş"})
        ), 404

    except requests.RequestException as e:
        return jsonify({"error": str(e)}), 500

@app.route("/fetch_hourly_data_paginated", methods=["POST"])
def fetch_hourly_data_paginated():
    """
    Sayfalama ile canlı veri döndüren endpoint.
    """
    selected_ip = session.get("selected_device_ip")  # Seçili cihazın IP adresi
    data = request.json
    page = int(data.get("page", 1))
    per_page = int(data.get("per_page", 20))

    if not selected_ip:
        return jsonify({"error": "Lütfen önce bir cihaz seçin!"}), 400

    print(f"📡 IP: {selected_ip}, Sayfa: {page}, Veri Sayısı: {per_page}")

    try:
        # IP adresine göre cihazdan veri al
        url = (
            f"http://{selected_ip}:8085/get_hourly_data?page={page}&per_page={per_page}"
        )
        response = requests.get(url)
        response.raise_for_status()
        hourly_data = response.json()

        return jsonify(hourly_data)
    except requests.RequestException as e:
        return jsonify({"error": str(e)}), 500

@app.route("/hourly-data-detail", endpoint="hourly-data-detail")
def hourly_data_detail():
    return render_template(
        "datas/hourly_data_detail.html", page_title="Hourly Data Detail"
    )

# Daily Data
@app.route("/daily-data", endpoint="daily-data")
def daily_data():
    return render_template("datas/daily_data.html", page_title="Daily Data")

@app.route("/fetch_grouped_daily_data", methods=["POST"])
def fetch_grouped_daily_data():
    selected_ip = session.get("selected_device_ip")
    if not selected_ip:
        return jsonify({"error": "Lütfen önce bir cihaz seçin!"}), 400

    try:
        url = f"http://{selected_ip}:8085/get_grouped_daily_data"
        response = requests.get(url)
        response.raise_for_status()
        daily_data = response.json().get("data", [])

        return (
            jsonify({"equipments": daily_data})
            if daily_data
            else jsonify({"message": "Bu tablo boş"})
        ), 404

    except requests.RequestException as e:
        return jsonify({"error": str(e)}), 500

@app.route("/fetch_daily_data_paginated", methods=["POST"])
def fetch_daily_data_paginated():
    """
    Sayfalama ile canlı veri döndüren endpoint.
    """
    selected_ip = session.get("selected_device_ip")
    data = request.json
    page = int(data.get("page", 1))
    per_page = int(data.get("per_page", 20))

    if not selected_ip:
        return jsonify({"error": "Lütfen önce bir cihaz seçin!"}), 400
    print(f"IP: {selected_ip}, Sayfa: {page}, Veri Sayısı: {per_page}")
    try:
        # IP adresine göre cihazdan veri al
        url = (
            f"http://{selected_ip}:8085/get_daily_data?page={page}&per_page={per_page}"
        )
        response = requests.get(url)
        response.raise_for_status()
        daily_data = response.json()

        return jsonify(daily_data)
    except requests.RequestException as e:
        return jsonify({"error": str(e)}), 500


@app.route("/daily-data-detail", endpoint="daily-data-detail")
def daily_data_detail():
    return render_template(
        "datas/daily_data_detail.html", page_title="Daily Data Detail"
    )
# !! Data End

# !! Alarm Start
@app.route("/alarm", endpoint="alarm")
def alarm():
    return render_template("alarms/alarm.html", page_title="Alarm")

@app.route("/network-alarm-detail", endpoint="network_alarm_detail")
def network_alarm_detail():
    return render_template(
        "alarms/network-alarm_details.html", page_title="Network Alarm Details"
    )

@app.route("/get_network_alarm_data")
def get_network_alarm_data():
    selected_ip = session.get("selected_device_ip")

    logging.info(f"Network Alarm Detayları İstendi - Seçili IP: {selected_ip}")

    if not selected_ip:
        logging.warning("Cihazın seri numarası bulunamadı!")
        return jsonify({"error": "Cihazın seri numarası bulunamadı."}), 400

    try:
        url_alarm = f"http://{selected_ip}:8085/get_network_alarms"
        logging.info(f"📡 Alarm verileri için istek gönderiliyor: {url_alarm}")

        response_alarm = requests.get(url_alarm, params={"serial_number": selected_ip}, timeout=5)
        response_alarm.raise_for_status()

        alarms = response_alarm.json().get("data", [])

        logging.info(f"{len(alarms)} Alarm Verisi Alındı")

        return jsonify({"status": "success", "data": alarms})

    except requests.exceptions.RequestException as e:
        logging.error(f"Alarm verileri alınamadı: {e}")
        return jsonify({"status": "error", "message": f"Alarm verileri alınamadı: {e}"}), 500


@app.route("/electric-alarm-detail", endpoint="electric_alarm_detail")
def electric_alarm_detail():
    return render_template(
        "alarms/electric_alarm_details.html", page_title="Electric Alarm Details"
    )

@app.route("/get_electric_alarm_data")
def get_electric_alarm_data():
    selected_ip = session.get("selected_device_ip")

    logging.info(f"Electric Alarm Detayları İstendi - Seçili IP: {selected_ip}")

    if not selected_ip:
        logging.warning("Cihazın seri numarası bulunamadı!")
        return jsonify({"error": "Cihazın seri numarası bulunamadı."}), 400
    try:
        url_alarm = f"http://{selected_ip}:8085/get_electric_alarms"
        logging.info(f"Alarm verileri için istek gönderiliyor: {url_alarm}")

        response_alarm = requests.get(url_alarm, params={"serial_number": selected_ip}, timeout=5)
        response_alarm.raise_for_status()

        alarms = response_alarm.json().get("data", [])

        logging.info(f"{len(alarms)} Alarm Verisi Alındı")

        return jsonify({"status": "success", "data": alarms})

    except requests.exceptions.RequestException as e:
        logging.error(f"Alarm verileri alınamadı: {e}")
        return jsonify({"status": "error", "message": f"Alarm verileri alınamadı: {e}"}), 500


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/get_slave_data", methods=["GET"])
def get_slave_data():
    selected_ip = session.get("selected_device_ip")

    if not selected_ip:
        return ResponseHandler.error(
            message="Device IP missing",
            code=400,
            details="Selected device IP is required",
        )
    try:
        url = f"http://{selected_ip}:8085/scan_all"
        response = requests.get(url, timeout=500)  
        response.raise_for_status()
        try:
            result = response.json()
        except ValueError:
            return ResponseHandler.error(
                message="Invalid JSON response",
                code=500,
                details="Failed to parse JSON response from device.",
            )

        if result.get("status") == "success":
            return ResponseHandler.success(
                message="Successful", data=result.get("data", [])
            )

        return ResponseHandler.error(
            message="Failed",
            code=400,
            details=result.get("message", "No valid response"),
        )

    except requests.Timeout:
        return ResponseHandler.error(
            message="Request timeout",
            code=504,
            details=f"Timeout while connecting to {selected_ip}",
        )

    except requests.RequestException as e:
        return ResponseHandler.error(
            message="Device connection error",
            code=500,
            details=f"Failed to connect to {selected_ip}: {str(e)}",
        )

    except Exception as e:
        return ResponseHandler.error(
            message="Unexpected error occurred", code=500, details=str(e)
        )

# Logs
@app.route("/log", endpoint="log")
def log():
    return render_template("logs/log.html", page_title="Log")

@app.route("/get_logs", methods=["POST"])
def get_logs():
    selected_ip = session.get("selected_device_ip")
    if not selected_ip:
        logging.error("Selected device IP not found.")
        return jsonify({"error": "Cihazın seri numarası bulunamadı."}), 400
    try:
        data = request.get_json()  
        if not data:
            logging.error("No data received in the request.")
            return jsonify({"error": "No data received"}), 400

        year = data.get("year")
        month = data.get("month")
        day = data.get("day")
        hour = data.get("hour", None)  
        
        logging.info(f"Fetching logs with params: Year: {year}, Month: {month}, Day: {day}, Hour: {hour}")

        url_alarm = f"http://{selected_ip}:8085/get_all_logs"
        params = {
            "year": year,
            "month": month,
            "day": day,
            "hour": hour
        }
        response_alarm = requests.get(url_alarm, params=params, timeout=5)
        response_alarm.raise_for_status()

        logs = response_alarm.json().get("data", [])
        logging.info(f"Fetched {len(logs)} logs successfully.")
        return jsonify({"status": "success", "data": logs})

    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching logs: {e}")
        return jsonify({"status": "error", "message": f"LOGS verileri alınamadı: {e}"}), 500
   
class ResponseHandler:
    @staticmethod
    def success(message=None, data=None):
        response = {"status": "success", "message": message, "data": data}
        return jsonify(response), 200

    @staticmethod
    def error(message="An error occurred", code=500, details=None):
        response = {
            "status": "error",
            "message": message,
            "error": {"code": code, "details": details},
        }
        return jsonify(response), code

if __name__ == "__main__":
    app.run(debug=True, port=5004)
