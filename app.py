import requests
from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    redirect,
    url_for,
    session,
    g,
    flash,
)
import mysql.connector
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from flask_scss import Scss
import ipaddress
import scapy.all as scapy
import nmap
from datetime import datetime, timedelta
import logging
from flask_babel import Babel, gettext as _

from blueprints.auth_routes import auth_bp
from blueprints.dashboard import dash_bp 
from utils.context_processors import inject_globals 
from utils.decorators import role_required  
from utils.helpers import get_base_url, DB_CONFIG, IP_RANGE

from blueprints.auth_routes import get_token_and_base_url
from utils.helpers import get_base_url
from utils.token_handler import TokenManager


app = Flask(__name__)
logger = logging.getLogger(__name__)
app.secret_key = "supersecretkey"
app.config["JWT_SECRET_KEY"] = "jwt_secret_key"
app.config['BABEL_DEFAULT_LOCALE'] = 'tr'
app.config['BABEL_SUPPORTED_LOCALES'] = ['en', 'tr', 'de']

CORS(app)
jwt = JWTManager(app)
Scss(app, static_dir="static", asset_dir="assets")
babel = Babel(app)

# LARAVEL_API_URL = "https://api.pierenergytrackingsystem.com/v1/orc24"  bunu sileyim mi o zaman ??  ?? 
# IP_RANGE = "192.168.4.0/24"
# DB_CONFIG = {"host": "localhost", "user": "root", "password": "123", "database": "iot"}
last_connection_time = None

# Blueprintleri kayıt et
app.register_blueprint(auth_bp)
app.register_blueprint(dash_bp)

# Context Processor - Global Değişkenler
app.context_processor(inject_globals)

# @app.before_request
# def before_request_func():
#     g.lang = session.get('lang', 'en') 
    
@app.before_request
def before_request_func():
    g.lang = session.get('lang', 'en') 
    print("Aktif oturum dili:", g.lang)

# Dil seçimi için Babel'le ilgili fonksiyon
@babel.localeselector
def get_locale():
    lang = session.get('lang', 'en')  
    logging.debug(f"GET LOCALE: Aktif Dil: {lang}")  
    return lang

@app.route('/set_language', methods=['POST'])
def set_language():
    lang = request.form.get("lang")
    if lang in ['en', 'tr', 'de']:
        session['lang'] = lang  
        logging.debug(f"SET LANGUAGE: Seçilen dil: {lang}")
    else:
        logging.debug(f"SET LANGUAGE: Geçersiz dil seçimi: {lang}")  
    return redirect(request.referrer or url_for("index"))  

@app.context_processor
def inject_locale():
    from flask_babel import get_locale
    return dict(get_locale=get_locale)

@app.route("/")
def index():
    return render_template("index.html")

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
        # f"{LARAVEL_API_URL}/alarm/status", headers=headers, verify=False
        f"{get_base_url()}/v1/orc24/alarm/status", headers=headers, verify=False
    )

    print("Alarm Status API Yanıtı:", response.status_code, response.text)

    if response.status_code == 200:
        return jsonify(response.json())
    else:
        return jsonify({"error": "Alarm status verisi alınamadı"}), response.status_code

def arp_scan(ip_range):
    """Belirtilen IP aralığında ARP taraması yaparak 02, 12 veya 2C ile başlayan MAC adreslerini bulur"""
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    ip_list = []
    for element in answered_list:
        mac_address = element[1].hwsrc.lower()  # MAC adresini küçük harfe çevir
        if mac_address.startswith("02") or mac_address.startswith("12") or mac_address.startswith("2c") or mac_address.startswith("d8"):
            ip_list.append({"ip": element[1].psrc, "mac": mac_address})

    return ip_list

# def nmap_scan(ip_range):
#     """Belirtilen IP aralığında Nmap taraması yaparak 02 veya 12  veya 2c ile başlayan MAC adreslerini bulur"""
#     nm = nmap.PortScanner()
#     # res = nm.scan(hosts=ip_range, arguments="-sn --unprivileged")
#     res = nm.scan(hosts=ip_range, arguments="-sn")
#     ip_list = []
#     for host in nm.all_hosts():
#         mac_address = nm[host]["addresses"].get("mac", "")
#         if mac_address.startswith("02") or mac_address.startswith("12") or mac_address.startswith("2c") or mac_address.startswith("d8"):
#             ip_list.append({"ip": host, "mac": mac_address})

#     return ip_list

def nmap_scan(ip_range):
    nm = nmap.PortScanner()

    # -sn: Ping taraması, -n: DNS çözümleme kapalı, --disable-arp-ping: bazen işe yarar
    print(f"Taranıyor: {ip_range} ...")
    nm.scan(hosts=ip_range, arguments="-sn -n")

    # mac_prefixes = ("2c", "d8")  
    mac_prefixes = ("2c","d8") 
    found_hosts = []

    for host in nm.all_hosts():
        addresses = nm[host].get("addresses", {})
        mac_address = addresses.get("mac", "").lower()

        if not mac_address:
            print(f"[!] {host} için MAC adresi alınamadı")
            continue

        if mac_address.startswith(mac_prefixes):
            found_hosts.append({"ip": host, "mac": mac_address})
            print(f"[+] Bulundu: {host} -> {mac_address}")

    return found_hosts

# !! VPN ile cihaz ip lerini getiren kod
# def get_mac_from_device(ip): 
#     """Cihaza HTTP isteği atarak MAC adresini almaya çalışır"""
#     try:
#         response = requests.get(f"http://{ip}:8085/mac_address", timeout=2)
#         if response.status_code == 200:
#             return response.text.strip()  
#     except requests.exceptions.RequestException:
#         pass
#     return None

# def nmap_scan(ip_range): 
#     """Belirtilen IP aralığında Nmap taraması yapar ve cihazlardan MAC adresi ister"""
#     nm = nmap.PortScanner()
#     res = nm.scan(hosts=ip_range, arguments="-sn --unprivileged")
#     print("Nmap taraması sonucu:", res) 
    
#     valid_devices = []
    
#     for host in nm.all_hosts():
#         print(f"Bulunan cihaz IP'si: {host}") 
#         mac_address = get_mac_from_device(host)  
#         print(f"MAC Adresi: {mac_address}")  
#         if mac_address and (mac_address.startswith("02") or mac_address.startswith("12") or mac_address.startswith("2c")):
#             valid_devices.append({"ip": host, "mac": mac_address})
#     return valid_devices
# !! VPN ile cihaz ip lerini getiren kod

# def get_connected_devices():
#     """Önce ARP taraması, başarısız olursa Nmap taraması ile cihazları bulur"""
#     devices = arp_scan(IP_RANGE)
#     if not devices:
#         print("ARP taraması başarısız, Nmap taraması başlatılıyor...")
#         devices = nmap_scan(IP_RANGE)
#     print("Bağlı cihazlar:", devices)
#     return devices

def get_connected_devices():
    devices = arp_scan(IP_RANGE)
    if not devices:
        print("ARP taraması başarısız, Nmap taraması başlatılıyor...")
        devices = nmap_scan(IP_RANGE)

    for device in devices:
        mac = device["mac"]
        ip = device["ip"]
        try:
            response = requests.get(
                f"http://{ip}:8085/get_modem_name_by_mac", 
                params={"mac": mac},
                timeout=3
            )
            if response.status_code == 200:
                name = response.json()["data"]["modem_name"]
                device["name"] = name
            else:
                device["name"] = "Unknown"
        except Exception as e:
            print(f"{ip} için modem adı alınamadı: {e}")
            device["name"] = "Not Connection"

        device["ip"] = ip  
        device["mac"] = mac

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
        # Asıl Flask uygulamasının çalıştığı endpointi kontrol et
        url = f"http://{ip_address}:8085/execute_command"
        payload = {"command": "echo test"}

        response = requests.post(url, json=payload, timeout=5)
        response.raise_for_status()

        if response.json().get("status") == "success":
            session["selected_device_ip"] = ip_address  
            session.permanent = True 
            return jsonify(success=True)
        else:
            return jsonify(success=False, error="Cihaz yanıt vermiyor veya hata döndü.")

    except requests.exceptions.RequestException as e:
        return jsonify(success=False, error=f"Bağlantı hatası: {str(e)}")

# ORC Status
@app.route("/orc-status", methods=["GET", "POST"], endpoint="orc_status")
def orc_status():
    selected_ip = session.get("selected_device_ip")

    if not selected_ip:
        flash(_("Please select a device first!"), "danger")
        return render_template(
            "orc_status/orc_status.html",
            page_title=_("ORC Status"),
            error=_("Please select a device first!"),
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

        url_network = f"http://{selected_ip}:8085/check_network"
        try:
            response_network = requests.get(url_network, timeout=5)
            response_network.raise_for_status()
            network_full = response_network.json()
            network_data = network_full.get("data", {})

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
            page_title=_("ORC Status"),
            modem=selected_modem,
            network=network_data,
            error=None,
        )

    except Exception as e:
        return render_template(
            "orc_status/orc_status.html",
            page_title=_("ORC Status"),
            error=_("Unexpected error: ") + str(e),
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
        # 📡 Seçili IP'deki cihazdan modem bilgisi alınır
        url_modem = f"http://{selected_ip}:8085/get_modems"
        print(f"[INFO] Modem bilgisi isteniyor: {url_modem}")
        response = requests.get(url_modem, timeout=5)
        response.raise_for_status()

        # 🌐 Gelen yanıt kontrol edilir
        modems = response.json().get("data", [])

        if not modems:
            print("[WARN] Modem listesi boş!")
            return ResponseHandler.error(
                message="No modem data found", code=404, details="Modem list is empty"
            )

        modem = modems[0]
        print(f"[INFO] İlk modem verisi alındı: {modem}")

        # 🎯 Gerekli tüm alanlar JSON nesnesine eklenir
        modem_info = {
            "name": modem.get("name", "Unknown"),
            "status": "Active" if modem.get("status") == 1 else "Inactive",
            "network_ssid": modem.get("network_ssid", "-"),
            "network_password": modem.get("network_password", "-"),
            "gsm_number": modem.get("gsm_number", ""),
            "brand_id": modem.get("brand_id"),
            "modem_model_id": modem.get("modem_model_id"),
            "local_ip_address": modem.get("local_ip_address"),
        }

        print(f"[SUCCESS] Modem info JSON oluşturuldu: {modem_info}")
        return ResponseHandler.success(
            message=_("Modem info retrieved successfully"), data=modem_info
        )

    except requests.RequestException as e:
        print(f"[ERROR] İstek hatası: {e}")
        return ResponseHandler.error(
            message=_("Failed to fetch modem data"), code=500, details=str(e)
        )
    except Exception as e:
        print(f"[ERROR] Genel hata: {e}")
        return ResponseHandler.error(
            message=_("Unexpected error occurred"), code=500, details=str(e)
        )

@app.route("/update_modem_info", methods=["POST"])
def update_modem_info():
    data = request.get_json()

    selected_ip = session.get("selected_device_ip")
    if not selected_ip:
        return ResponseHandler.error(message="Selected device IP missing", code=400)

    # 1️⃣ UUID'yi ve diğer bilgileri cihazdan çek (/get_modems)
    try:
        response = requests.get(f"http://{selected_ip}:8085/get_modems", timeout=5)
        response.raise_for_status()
        modems = response.json().get("data", [])
        if not modems:
            return ResponseHandler.error(message="No modem data found", code=404)

        modem_uuid = modems[0].get("uuid")
        if not modem_uuid:
            return ResponseHandler.error(message="UUID not found", code=404)
    except Exception as e:
        return ResponseHandler.error(message="Failed to get modem info", code=500, details=str(e))

    # ⬅️ UUID'yi cihaz tarafına gönderilecek veri içine ekle
    data["uuid"] = modem_uuid

    # 2️⃣ Yerel Güncelleme (Cihazdaki /update_modem endpointine gönderilir)
    try:
        local_update_url = f"http://{selected_ip}:8085/update_modem"
        local_response = requests.post(local_update_url, json=data, timeout=5)
        local_response.raise_for_status()
    except Exception as e:
        return ResponseHandler.error(message="Local update failed", code=500, details=str(e))

    # 3️⃣ Bulut Güncellemesi (Pier Cloud API'sine PUT isteği)
    token = session.get("access_token")
    if not token:
        return ResponseHandler.error(message="Token missing", code=401)
    _, base_url = get_base_url()
    cloud_url = f"{base_url}/orc24/modems/{modem_uuid}"

    # cloud_url = f"https://v2.pierenergytrackingsystem.com/api/iot/v2/orc24/modems/{modem_uuid}"
    try:
        cloud_response = requests.put(
            cloud_url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
                "Content-Type": "application/json"
            },
            json=data,
            verify=False
        )
        cloud_response.raise_for_status()
    except Exception as e:
        return ResponseHandler.error(message="Cloud update failed", code=500, details=str(e))

    return ResponseHandler.success(message="Modem updated locally and on cloud")

@app.route("/get_equipment_from_cloud/<string:uuid>", methods=["GET"])
def get_equipment_from_cloud(uuid):
    token = session.get("access_token")
    if not token:
        return jsonify({"status": "error", "message": "Token missing"}), 401

    cloud_url = f"https://v2.pierenergytrackingsystem.com/api/iot/v2/orc24/equipments/{uuid}"

    try:
        response = requests.get(
            cloud_url,
            headers={"Authorization": f"Bearer {token}"},
            verify=False
        )
        response.raise_for_status()
        return jsonify({"status": "success", "data": response.json()})
    except Exception as e:
        return jsonify({"status": "error", "message": "Failed to fetch data", "details": str(e)}), 500

@app.route("/update_equipment_cloud/<string:uuid>", methods=["PUT"])
def update_equipment_cloud(uuid):
    token = session.get("access_token")
    if not token:
        return jsonify({"status": "error", "message": "Token missing"}), 401

    data = request.get_json()

    cloud_url = f"https://v2.pierenergytrackingsystem.com/api/iot/v2/orc24/equipments/{uuid}"

    try:
        response = requests.put(
            cloud_url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
                "Content-Type": "application/json"
            },
            json=data,
            verify=False
        )
        response.raise_for_status()
        return jsonify({"status": "success", "message": "Equipment updated on cloud"})
    except Exception as e:
        return jsonify({"status": "error", "message": "Cloud update failed", "details": str(e)}), 500

@app.route("/sync_equipment_local/<string:uuid>", methods=["GET"])
def sync_equipment_local(uuid):
    token = session.get("access_token")
    selected_ip = session.get("selected_device_ip")
    selected_equipment_id = session.get("selected_equipment_id")

    if not token or not selected_ip or not selected_equipment_id:
        return jsonify({"status": "error", "message": "Token, IP veya Equipment ID eksik"}), 400

    # 1️⃣ Buluttan veriyi çek
    cloud_url = f"https://v2.pierenergytrackingsystem.com/api/iot/v2/orc24/equipments/{uuid}"
    try:
        response = requests.get(
            cloud_url,
            headers={"Authorization": f"Bearer {token}"},
            verify=False
        )
        response.raise_for_status()
        cloud_data = response.json()
    except Exception as e:
        return jsonify({"status": "error", "message": "Bulut verisi alınamadı", "details": str(e)}), 500

    # 2️⃣ Cihaza POST ile gönder
    try:
        device_sync_url = f"http://{selected_ip}:8085/sync_equipment_from_cloud"
        payload = {
            "equipment_id": selected_equipment_id,
            "installation_power": cloud_data.get("installation_power"),
            "phase_1_current": cloud_data.get("phase_1_current"),
            "phase_2_current": cloud_data.get("phase_2_current"),
            "phase_3_current": cloud_data.get("phase_3_current"),
        }

        device_response = requests.post(device_sync_url, json=payload, timeout=5)
        device_response.raise_for_status()
    except Exception as e:
        return jsonify({"status": "error", "message": "Cihaza sync başarısız", "details": str(e)}), 500

    return jsonify({"status": "success", "message": "Bulut verisi cihaza senkronize edildi"})

# network info
@app.route("/wi-fi-list", methods=["POST"])
def wi_fi_list():
    selected_ip = session.get("selected_device_ip")

    if not selected_ip:
        print("ERROR: No selected device IP found!")
        return jsonify({"error": "IP address is missing"}), 400

    try:
        print(f"Wi-Fi listesi için cihazdan veri alınıyor: {selected_ip}")
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
        return jsonify({"error": "Ekipman seçilmedi. Lütfen önce bir ekipman seçin!"}), 400

    print(f"Backend'e Gelen Equipment ID: {equipment_id}")

    try:
        url = f"http://{selected_ip}:8085/get_equipment_details/{equipment_id}"
        print(f"📡 Equipment detaylarını çekiyor: {url}")

        response = requests.get(url, timeout=10)

        if response.status_code != 200:
            print(f"❌ HATA: {response.status_code} - {response.text}")
            return jsonify({"error": f"Modbus bağlantı hatası: {response.text}"}), response.status_code

        equipment_data = response.json()
        return jsonify(equipment_data)

    except requests.Timeout:
        print("❌ Modbus bağlantısı zaman aşımına uğradı.")
        return jsonify({"error": "Modbus bağlantısı zaman aşımına uğradı."}), 500
    except requests.ConnectionError:
        print("❌ Modbus bağlantısı kurulamadı.")
        return jsonify({"error": "Modbus bağlantısı kurulamadı."}), 500
    except requests.RequestException as e:
        print(f"❌ Modbus bağlantı hatası: {e}")
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

# @app.route("/modbus_test", methods=["POST", "GET"])
# def modbus_test():
#     """Check if the selected device has a valid Modbus connection."""
#     selected_ip = session.get("selected_device_ip")
#     print(f"[INFO] Selected IP from session: {selected_ip}")

#     if not selected_ip:
#         print("[ERROR] Device IP is missing in session.")
#         return ResponseHandler.error(
#             message="Device IP missing",
#             code=400,
#             details="Selected device IP is required",
#         )

#     try:
#         url = f"http://{selected_ip}:8085/modbus_test"
#         print(f"[INFO] Sending request to: {url}")
#         response = requests.get(url)
#         response.raise_for_status()

#         result = response.json()
#         print(f"[INFO] Response received: {result}")

#         if result.get("status") == "success":
#             print("[SUCCESS] Modbus test passed.")
#             return ResponseHandler.success(
#                 message="Modbus test successful", data=result.get("data", [])
#             )

#         print("[ERROR] Modbus test failed with message:", result.get("message"))
#         return ResponseHandler.error(
#             message="Modbus test failed",
#             code=400,
#             details=result.get("message", "No valid Modbus response"),
#         )

#     except requests.RequestException as e:
#         print(f"[EXCEPTION] Connection error: {str(e)}")
#         return ResponseHandler.error(
#             message="Device connection error",
#             code=500,
#             details=f"Failed to connect to {selected_ip}: {str(e)}",
#         )

#     except Exception as e:
#         print(f"[EXCEPTION] Unexpected error: {str(e)}")
#         return ResponseHandler.error(
#             message="Unexpected error occurred", code=500, details=str(e)
#         )

@app.route("/modbus_test", methods=["POST"])
def modbus_test_proxy():
    selected_ip = session.get("selected_device_ip")
    data = request.get_json()
    slave_id = data.get("slave_id")

    if not selected_ip or not slave_id:
        return ResponseHandler.error(
            message="Device IP or Slave ID missing",
            code=400,
            details="Both Device IP and Slave ID are required",
        )

    try:
        url = f"http://{selected_ip}:8085/modbus_test"
        response = requests.post(url, json={"slave_id": slave_id})
        response.raise_for_status()

        result = response.json()

        if result.get("status") == "success":
            return ResponseHandler.success(
                message=f"Slave ID {slave_id} connected on port {result['data'][0]['port']}",
                data=result.get("data", [])
            )

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
        print(f"📡 İstek yapılıyor: {url}")  

        response = requests.get(url, timeout=20)
        response.raise_for_status()
        equipment_data = response.json()

        if "status" in equipment_data and equipment_data["status"] == "error":
            print("Hata: Backend'ten gelen error mesajı:", equipment_data)
            return jsonify({"error": equipment_data["message"]}), 500

        # **Equipment verisini session içinde tutabiliriz**
        session["equipment_data"] = equipment_data
        print(f"Başarıyla çekildi: {len(equipment_data['data'])} ekipman bulundu.")

        return jsonify(equipment_data)

    except requests.exceptions.Timeout:
        print("Zaman aşımı hatası!")
        return jsonify({"error": "Timeout: Ekipman verisi alınamadı."}), 500
    except requests.exceptions.ConnectionError:
        print("Bağlantı hatası! Flask instance'ı çalışıyor mu?")
        return jsonify({"error": "Connection Error: Flask instance'ı çalışıyor mu?"}), 500
    except requests.exceptions.RequestException as e:
        print(f"RequestException: {e}")
        return jsonify({"error": f"Modbus bağlantı hatası: {str(e)}"}), 500

@app.route("/equipments-all", methods=["POST"])
def equipments_all():
    selected_ip = session.get("selected_device_ip")

    if not selected_ip:
        return jsonify({"error": "IP adresi belirtilmedi"}), 400
    try:
        url = f"http://{selected_ip}:8085/get_all_equipments"
        print(f"Diğer Flask'a istek gönderiliyor: {url}")

        response = requests.get(url, timeout=10)
        response.raise_for_status()
        equipment_data = response.json()

        if equipment_data.get("status") == "error":
            print("Backend hata döndürdü:", equipment_data.get("message"))
            return jsonify({"error": equipment_data.get("message")}), 500

        print(f"{len(equipment_data['data'])} kayıt alındı.")
        return jsonify(equipment_data)

    except requests.exceptions.Timeout:
        print("⏱ Zaman aşımı!")
        return jsonify({"error": "Timeout: Ekipman verisi alınamadı."}), 500
    except requests.exceptions.ConnectionError:
        print("🔌 Bağlantı hatası!")
        return jsonify({"error": "Flask instance'a bağlanılamadı."}), 500
    except Exception as e:
        print(f"Genel hata: {e}")
        return jsonify({"error": f"Beklenmedik hata: {str(e)}"}), 500

@app.route("/get-all-equipments", methods=["POST"])
def get_all_equipments():
    selected_ip = session.get("selected_device_ip")
    if not selected_ip:
        return jsonify({"error": "IP adresi belirtilmedi"}), 400
    try:
        url = f"http://{selected_ip}:8085/get_equipments"
        print(f"İstek yapılıyor: {url}")

        response = requests.get(url, timeout=20)
        response.raise_for_status()
        equipment_data = response.json()

        if "status" in equipment_data and equipment_data["status"] == "error":
            print("Hata: Backend'ten gelen error mesajı:", equipment_data)
            return jsonify({"error": equipment_data["message"]}), 500

        # **Equipment verisini session içinde tutabiliriz**
        session["equipment_data"] = equipment_data
        print(f"Başarıyla çekildi: {len(equipment_data['data'])} ekipman bulundu.")

        return jsonify(equipment_data)

    except requests.exceptions.Timeout:
        print("Zaman aşımı hatası!")
        return jsonify({"error": "Timeout: Ekipman verisi alınamadı."}), 500
    except requests.exceptions.ConnectionError:
        print("Bağlantı hatası! Flask instance'ı çalışıyor mu?")
        return jsonify({"error": "Connection Error: Flask instance'ı çalışıyor mu?"}), 500
    except requests.exceptions.RequestException as e:
        print(f"RequestException: {e}")
        return jsonify({"error": f"Modbus bağlantı hatası: {str(e)}"}), 500

@app.route("/equipment", endpoint="equipment")
def equipment():
    return render_template("equipments/equipments.html", page_title=_("Equipments"))

@app.route("/equipment-setting", methods=["GET"])
def equipment_setting():
    modbus_data = session.get("modbus_data", [])
    return render_template(
        "equipments/equipment_setting.html",
        modbus_data=modbus_data,
        page_title=_("Equipment Setting"),
    )

# Diger Sayfalar
@app.route("/modem-selection", endpoint="modem_selection")
def modem_selection():
    return render_template("modem_selection.html", page_title=_("Modem Selection"))

@app.route("/switch", endpoint="switch")
@role_required('manager')
def switch():
    return render_template("test/switch.html", page_title=_("Test Mode") )

@app.route("/test", endpoint="test")
def test():
    return render_template("test/test.html", page_title=_("Test"))

@app.route("/test-ui", endpoint="test-ui")
def test():
    return render_template("test_ui.html", page_title=_("Test UI"))

@app.route("/equipment-details", endpoint="equipment_details")
def equipment_details():
    return render_template("equipments/equipment_details.html", page_title=_("Equipments Details"))

@app.route("/settings", endpoint="settings")
def settings():
    return render_template("settings/setting.html", page_title=_("Settings"))

@app.route("/orc-settings", endpoint="orc_settings")
def orc_setting():
    return render_template("settings/orc_set.html", page_title=_("Orc Settings"))

@app.route("/osos-settings", endpoint="osos_settings")
def osos_setting():
    return render_template("settings/osos_set.html", page_title=_("Osos Settings"))

@app.route("/equipment-settings", endpoint="equipment_settings")
def equipment_setting():
    return render_template("settings/equipment_set.html", page_title=_("Equipment Settings"))

@app.route("/send_command", methods=["POST"])
def send_command():
    selected_ip = session.get("selected_device_ip")
    if not selected_ip:
        return ResponseHandler.error(
            message="Device IP missing",
            code=400,
            details="Selected device IP is required",)
    data = request.json
    command = data.get("command")
    if not command:
        return ResponseHandler.error(
            message="Command missing", code=400, details="Command is required")
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

@app.route("/data", endpoint="data")
def data():
    return render_template("datas/data.html", page_title=_("Data"))

# Live Data
@app.route("/live-data", endpoint="live-data")
def live_data():
    return render_template("datas/live_data.html", page_title=_("Live Data"))

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
    selected_ip = session.get("selected_device_ip") 
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
    return render_template("datas/live_data_detail.html", page_title=_("Live Data Detail"))

# Hourly Data
@app.route("/hourly-data", endpoint="hourly-data")
def hourly_data():
    return render_template("datas/hourly_data.html", page_title=_("Hourly Data"))

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
    selected_ip = session.get("selected_device_ip") 
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
        "datas/hourly_data_detail.html", page_title=_("Hourly Data Detail"))

# Daily Data
@app.route("/daily-data", endpoint="daily-data")
def daily_data():
    return render_template("datas/daily_data.html", page_title=_("Daily Data"))

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
        "datas/daily_data_detail.html", page_title=_("Daily Data Detail"))

@app.route("/alarm", endpoint="alarm")
def alarm():
    return render_template("alarms/alarm.html", page_title=_("Alarm"))

@app.route("/network-alarm-detail", endpoint="network_alarm_detail")
def network_alarm_detail():
    return render_template(
        "alarms/network_alarm_details.html", page_title=_("Network Alarm Details")
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
        "alarms/electric_alarm_details.html", page_title=_("Electric Alarm Details"))

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

@app.route("/get_slave_data", methods=["GET"])
def get_slave_data():
    selected_ip = session.get("selected_device_ip")

    if not selected_ip:
        print("🚨 HATA: Seçili cihazın IP'si yok!")
        return ResponseHandler.error(message="Device IP missing", code=400)
    try:
        url = f"http://{selected_ip}:8085/scan_all"
        print(f"🔍 {selected_ip} adresine istek gönderiliyor: {url}")

        response = requests.get(url, timeout=500)
        print(f"✅ API Yanıt Durumu: {response.status_code}")

        response.raise_for_status()
        result = response.json()
        print(f"✅ API JSON Yanıtı: {result}")

        if result.get("status") == "success":
            return ResponseHandler.success(message="Successful", data=result.get("data", []))

        return ResponseHandler.error(message="Failed", code=400, details=result.get("message", "No valid response"))

    except requests.Timeout:
        print(f"⏳ {selected_ip} yanıt vermedi, zaman aşımı!")
        return ResponseHandler.error(message="Request timeout", code=504)

    except requests.RequestException as e:
        print(f"❌ Cihaz bağlantı hatası: {e}")
        return ResponseHandler.error(message="Device connection error", code=500)

    except Exception as e:
        print(f"❌ Beklenmedik hata: {e}")
        return ResponseHandler.error(message="Unexpected error", code=500)

# Logs
@app.route("/log", endpoint="log")
def log():
    return render_template("logs/log.html", page_title=_("Logs"))

@app.route("/get_logs", methods=["POST"])
def get_logs():
    selected_ip = session.get("selected_device_ip")
    if not selected_ip:
        logging.error("Selected device IP not found.")
        return jsonify({"error": "Cihazın seri numarası bulunamadı."}), 400
    try:
        data = request.get_json()
        year = data.get("year")
        month = data.get("month")
        day = data.get("day")
        hour = data.get("hour", None)
        page = data.get("page", 1)
        per_page = data.get("per_page", 20)

        # ŞU SATIR ÖNEMLİ (page ve per_page eklenmeli!)
        params = {
            "year": year,
            "month": month,
            "day": day,
            "page": page,
            "per_page": per_page
        }
        if hour:
            params["hour"] = hour
        url_alarm = f"http://{selected_ip}:8085/get_all_logs"
        response_alarm = requests.get(url_alarm, params=params, timeout=5)
        response_alarm.raise_for_status()

        logs_data = response_alarm.json()

        return jsonify({
            "status": "success",
            "data": logs_data["data"],
            "has_more": logs_data.get("has_more", False),
            "page": logs_data.get("page", page)
        })

    except requests.exceptions.RequestException as e:
        logging.error(f"[ERROR] Error fetching logs: {e}")
        return jsonify({"status": "error", "message": f"LOGS verileri alınamadı: {e}"}), 500


    except requests.exceptions.RequestException as e:
        logging.error(f"[ERROR] Error fetching logs: {e}")
        return jsonify({"status": "error", "message": f"LOGS verileri alınamadı: {e}"}), 500

@app.route("/get_archive_log_status", methods=["GET"])
def get_archive_log_status():
    logging.info("[FLASK A] Archive log status isteği alındı.")
    print("[DEBUG] ➡️  Archive log status isteği alındı.")

    selected_ip = session.get("selected_device_ip")
    print(f"[DEBUG] Seçilen IP: {selected_ip}")

    if not selected_ip:
        logging.error("[FLASK A] IP adresi bulunamadı (session boş olabilir).")
        print("[DEBUG] IP adresi bulunamadı! Session kontrol et.")
        return jsonify({"error": "Cihazın seri numarası bulunamadı."}), 400

    try:
        url = f"http://{selected_ip}:8085/get_archive_status"
        logging.info(f"[FLASK A] {selected_ip} adresine archive log isteği gönderiliyor.")
        print(f"[DEBUG] ➡️  İstek URL'si: {url}")

        response = requests.get(url, timeout=5)
        print(f"[DEBUG] 🌐 İstek atıldı, status code: {response.status_code}")

        response.raise_for_status()

        archive_status = response.json()
        print(f"[DEBUG] ✅ JSON veri alındı. Anahtarlar: {list(archive_status.keys())}")

        logging.info("[FLASK A] Archive log verisi başarıyla alındı.")
        return jsonify(archive_status)

    except requests.exceptions.Timeout:
        logging.error("[FLASK A] İstek zaman aşımına uğradı!")
        print("[DEBUG] ❌ Timeout hatası!")
        return jsonify({"status": "error", "message": "İstek zaman aşımına uğradı!"}), 504

    except requests.exceptions.ConnectionError:
        logging.error("[FLASK A] Bağlantı hatası oluştu!")
        print("[DEBUG] ❌ ConnectionError!")
        return jsonify({"status": "error", "message": "Cihaza bağlanılamadı!"}), 503

    except requests.exceptions.HTTPError as http_err:
        logging.error(f"[FLASK A] HTTP hatası: {http_err}")
        print(f"[DEBUG] ❌ HTTPError: {http_err}")
        return jsonify({"status": "error", "message": f"HTTP hatası: {http_err}"}), response.status_code

    except Exception as e:
        logging.error(f"[FLASK A] Genel hata: {e}")
        print(f"[DEBUG] ❌ Genel Exception: {e}")
        return jsonify({"status": "error", "message": f"Beklenmeyen hata: {e}"}), 500

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
