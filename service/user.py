import base64
import hashlib
import hmac
import calendar
import datetime
import jwt

from constants import PWD_HASH_SALT, PWD_HASH_ITERATIONS, SECRET_HERE, ALGO
from dao.user import UserDAO


class UserService:
    def __init__(self, dao: UserDAO):
        self.dao = dao

    def get_one(self, bid):
        return self.dao.get_one(bid)

    def get_all(self):
        return self.dao.get_all()

    def create(self, user_d):
        user_d["password"] = self.get_hash(user_d["password"])
        data = self.dao.create(user_d)
        return (
            {
                "username": data.username,
                "password": str(data.password),
                "role": data.role
            }
        )

    def update(self, user_d):
        self.dao.update(user_d)
        return self.dao

    def delete(self, rid):
        self.dao.delete(rid)

    def get_hash(self, password):
        return base64.b64encode(hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),  # Convert the password to bytes
            PWD_HASH_SALT,
            PWD_HASH_ITERATIONS
        ))

    def compare_passwords(self, password_hash, other_password) -> bool:
        return hmac.compare_digest(
            base64.b64decode(password_hash),
            hashlib.pbkdf2_hmac('sha256',
                                other_password.encode('utf-8'),
                                PWD_HASH_SALT,
                                PWD_HASH_ITERATIONS)
        )

    def tokens_gen(self, info, secret, algo):
        min30 = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        info["exp"] = calendar.timegm(min30.timetuple())
        access_token = jwt.encode(info, secret, algorithm=algo)

        days130 = datetime.datetime.utcnow() + datetime.timedelta(days=130)
        info["exp"] = calendar.timegm(days130.timetuple())
        refresh_token = jwt.encode(info, secret, algorithm=algo)

        return {"access_token": access_token, "refresh_token": refresh_token}

    def post_auth(self, data):
        user = self.dao.get_by_username(data.get('username'))
        if user:
            for i in user:
                if self.compare_passwords(i.password, data.get('password')):

                    info = {
                        "username": i.username,
                        "role": i.role
                    }

                    secret = SECRET_HERE
                    algo = 'HS256'

                    return self.tokens_gen(info, secret, algo)

            return {"error": 401}

    def put_auth(self, ref_token):
        # secret = SECRET_HERE
        # algo = 'HS256'

        try:
            data = jwt.decode(jwt=ref_token, key=SECRET_HERE, algorithms=[ALGO])
        except Exception as e:
            return {"error": 401}

        username = data.get("username")

        user = self.dao.get_by_username(username)
        if len(user) != 1:
            for u in user:
                if data['role'] == u.role:
                    user = u
                    break
        else:
            user = user[0]

        data = {
            "username": user.username,
            "role": user.role
        }

        return self.tokens_gen(data, SECRET_HERE, ALGO)

    def check_access_token(self, access_token) -> bool:
        try:
            data = jwt.decode(jwt=access_token, key=SECRET_HERE, algorithms=[ALGO])
            return data
        except Exception as e:
            return False

    def check_admin_role(self, access_token):
        if data := self.check_access_token(access_token):
            if data["role"] == 'admin':
                return True
        return False

