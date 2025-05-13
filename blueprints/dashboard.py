from flask import Blueprint, request, session, render_template
from utils.token_handler import get_dashboard_data
from utils.decorators import role_required  

dash_bp = Blueprint("dashboard", __name__)

@dash_bp.route("/dashboard")
@role_required("manager", "technical", "viewer")  
def dashboard():
    data, error = get_dashboard_data()

    if error:
        return render_template("dashboard.html", error=error)
    penalty_status = (
        data.get("capacitive", {}).get("isUnderPenalty", False)
        or data.get("inductive", {}).get("isUnderPenalty", False)
    )

    return render_template(
        "dashboard.html",
        from_grid=data.get("consumed_from_network", {}),
        total_generated=data.get("total_produced", {}),
        total_consumed=data.get("total_consumed", {}),
        voltages=data.get("voltages", {}),
        currents=data.get("current", {}),
        frequency=data.get("frequency", 0),
        power_factor=data.get("power_factor", 0),
        penalty_status=penalty_status
    )
