import base64

PWD_HASH_SALT = base64.b64decode('secret here'+ '==')
PWD_HASH_ITERATIONS = 100_000
SECRET_HERE = '249y823r9v8238r9u'
ALGO = 'HS256'
