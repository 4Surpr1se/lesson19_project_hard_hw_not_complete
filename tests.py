import base64
import hashlib


def get_hash(password):
    # lukimakioko
    salt = "lukimakioko"
    return base64.b64encode(hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),  # Convert the password to bytes
        base64.b64decode('secret here' + '=='),
        100_000
    ))


print(get_hash("1233333333asdaw311"))
