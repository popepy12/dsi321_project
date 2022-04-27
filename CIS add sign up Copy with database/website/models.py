from . import db, db2
from flask_login import UserMixin

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    studentid = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))


class AdminUser (db2.Model, UserMixin):
    id = db2.Column(db2.Integer, primary_key=True)
    adminid = db2.Column(db2.String(150), unique=True)
    adminpassword = db2.Column(db2.String(150))
