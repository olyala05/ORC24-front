# utils/context_processors.py
from flask import session
from flask_babel import get_locale

def inject_globals():
    return {
        'get_locale': get_locale,
        'user_role': session.get('client_role'),
        'user_name': session.get('client_name')
    }
