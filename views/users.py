import json

from flask import request
from flask_restx import Resource, Namespace

from dao.model.user import UserSchema
from implemented import user_service

user_ns = Namespace('users')
auth_ns = Namespace('auth')


@user_ns.route('/')
class UsersView(Resource):
    def get(self):
        rs = user_service.get_all()
        res = UserSchema(many=True).dump(rs)

        return res, 200

    def post(self):
        req_json = request.json
        return json.dumps(user_service.create(req_json))


@user_ns.route('/<int:bid>')
class UserView(Resource):
    def get(self, bid):
        b = user_service.get_one(bid)
        sm_d = UserSchema().dump(b)
        return sm_d, 200

    def put(self, bid):
        req_json = request.json
        if "id" not in req_json:
            req_json["id"] = bid
        user_service.update(req_json)
        return "", 204

    def delete(self, bid):
        user_service.delete(bid)
        return "", 204


@auth_ns.route('/')
class AuthView(Resource):
    def post(self):
        req_json = request.json
        return user_service.post_auth(req_json)
            # UserSchema(many=True).dump(user_service.post_auth(req_json))

    def put(self):
        token = request.headers['Authorization'].split("Bearer ")[-1]
        return user_service.put_auth(token)


