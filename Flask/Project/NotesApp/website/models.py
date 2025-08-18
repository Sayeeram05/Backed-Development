from sqlalchemy.sql import func
from .import db
from flask_login import UserMixin

class Notes(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    data = db.Column(db.String(15000),nullable=False)
    date = db.Column(db.DateTime(timezone=True),default = func.now())
    user_id = db.Column(db.Integer,db.ForeignKey('user.id')) # class Lower

class User(db.Model, UserMixin):
    id = db.Column(db.Integer,primary_key=True)
    email = db.Column(db.String(150),unique=True,nullable=False)
    name = db.Column(db.String(150),nullable=False)
    password = db.Column(db.String(150),nullable=False)
    notes = db.relationship("Notes")  # class Caps
    