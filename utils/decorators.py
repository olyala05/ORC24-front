from functools import wraps
from flask import session, redirect, url_for, flash

def role_required(*allowed_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if session.get('client_role') not in allowed_roles:
                flash("Bu sayfaya erişim yetkiniz yok!", "danger")
                return redirect(url_for('modem_selection'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator
