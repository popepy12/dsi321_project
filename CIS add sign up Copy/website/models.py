from . import db
from flask_login import UserMixin

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    studentid = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))

