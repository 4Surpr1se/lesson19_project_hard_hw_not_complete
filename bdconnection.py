# from dao.model.user import User
# from implemented import user_service
#
# from flask import Flask
# from flask_sqlalchemy import SQLAlchemy
#
# app = Flask(__name__)
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///./movies.db'
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# db = SQLAlchemy(app)
#
# user_password = "000"
# user_password = user_service.get_hash(user_password)
#
# u1 = User(username="000", password=user_password, role="admin")
#
# with db.session.begin():
#     db.session.add(u1)
#     print(db.session.query(User.password).all())
