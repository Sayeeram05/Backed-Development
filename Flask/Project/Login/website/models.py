from flask_login import UserMixin
from . import db


class User(db.Model, UserMixin):
    id = db.Column(db.Integer,primary_key=True)
    userName = db.Column(db.String(150),nullable=True)
    email = db.Column(db.String(150),unique=True,nullable=True)
    password = db.Column(db.String(200),nullable=True)