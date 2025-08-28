from . import Db

class User(Db.Model):
    
    id = Db.Column(Db.Integer,primary_key=True)
    Username = Db.Column(Db.String(150),nullable=True)
    Age = Db.Column(Db.Integer)
    Gender = Db.Column(Db.String(15))
    Password = Db.Column(Db.String(200),nullable=True)