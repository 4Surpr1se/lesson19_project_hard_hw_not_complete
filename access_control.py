from flask import request
from flask_restx import abort

from implemented import user_service


def auth_required(func):
    def wrapper(*args, **kwargs):
        if 'Authorization' not in request.headers:
            abort(401)

        data = request.headers['Authorization']
        token = data.split("Bearer ")[-1]

        if user_service.check_access_token(token):
            return func(*args, **kwargs)
        else:
            print("JWT Decode Exception")
            abort(401)
            return "no permission"

    return wrapper


def admin_required(func):
    def wrapper(*args, **kwargs):
        if 'Authorization' not in request.headers:
            abort(401)

        data = request.headers['Authorization']
        token = data.split("Bearer ")[-1]

        if user_service.check_admin_role(token):
            return func(*args, **kwargs)
        else:
            print("JWT Decode Exception")
            abort(401)
            return "no permission"

    return wrapper
