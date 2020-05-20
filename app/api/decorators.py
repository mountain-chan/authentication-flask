from functools import wraps
from flask_login import current_user
from app.utils import send_error


def permission_required(permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.can(permission):
                return send_error(message='Insufficient permissions!')
            return f(*args, **kwargs)

        return decorated_function

    return decorator
