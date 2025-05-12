from flask import Blueprint, request, session, render_template
from utils.token_handler import get_dashboard_data, TokenManager
from utils.rabbitmq_sender import send_rabbitmq_message
import socket
import uuid  # MAC adresi için

dash_bp = Blueprint("dashboard", __name__)

def get_mac_address():
    mac_num = hex(uuid.getnode()).replace('0x', '').upper()
    mac = ":".join(mac_num[i:i+2] for i in range(0, 12, 2))
    return mac

@dash_bp.route("/dashboard")
def dashboard():
    # 1. Dashboard verisini çek
    data, error = get_dashboard_data()

    # 2. RabbitMQ mesajını sadece ilk gelişte gönder
    if not session.get("rabbitmq_sent"):
        token = TokenManager.get_token()
        if token:
            try:
                hostname = socket.gethostname()
                local_ip = socket.gethostbyname(hostname)
                mac = get_mac_address()

                content = {
                    "vpn_ip_address": "10.8.0.10",  # Dinamik alınacaksa ayarla
                    "local_ip_address": local_ip,
                    "public_ip_address": "8.8.8.8",  # İstersen dinamik çözüm ekle
                    "mac_address": mac,
                    "end_mac_address": mac,
                    "operation_system_id": 1,
                    "model_id": 1,
                    "brand_type_id": 2,
                    "communication_protocol_id": 1,
                    "network_type_id": 2,
                    "communication_type_id": 1,
                    "version": "1.2.3",
                    "temperature_data": 10.5,
                    "cpu_usage": 11.5,
                    "total_memory": 12.5,
                    "used_memory": 13.5
                }

                message = {
                    "token": token,
                    "type": "modem",
                    "version": 2,
                    "content": content
                }

                if send_rabbitmq_message(message):
                    print("✅ RabbitMQ mesajı gönderildi.")
                    session["rabbitmq_sent"] = True
                else:
                    print("❌ RabbitMQ mesajı gönderilemedi.")
            except Exception as e:
                print(f"⚠️ RabbitMQ gönderim sırasında hata: {e}")
        else:
            print("⚠️ Token bulunamadı. RabbitMQ mesajı gönderilemedi.")

    # 3. API verisi hatalıysa sayfada hatayı göster
    if error or not data:
        return render_template("dashboard.html", error=error)

    # 4. Ceza durumu kontrolü (inductive/capacitive)
    penalty_status = (
        data.get("capacitive", {}).get("isUnderPenalty", False) or
        data.get("inductive", {}).get("isUnderPenalty", False)
    )

    # 5. Şablona veri gönder
    return render_template(
        "dashboard.html",
        from_grid=data.get("consumed_from_network", {"kwh": 0}),
        total_generated=data.get("total_produced", {}),
        total_consumed=data.get("total_consumed", {}),
        voltages=data.get("voltages", {}),
        currents=data.get("current", {}),
        frequency=data.get("frequency", 0),
        power_factor=data.get("power_factor", 0),
        penalty_status=penalty_status
    )
