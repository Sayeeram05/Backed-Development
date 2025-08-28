import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

Db = SQLAlchemy()
DbName = "database.db"

def CreateApp():
    app = Flask(__name__)
    
    app.config["SECRET_KEY"] = "EFQWEFFfewqf"
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DbName}"
    
    Db.init_app(app)
    
    
    from .views import Views
    
    app.register_blueprint(Views,url_prefix="/")
    
    # from .model import User
    CreateDatabase(app)
    
    return app

def CreateDatabase(app):
    Path = os.path.join("instance",DbName)
    print(Path)
    if not (os.path.exists(Path)):
        with app.app_context():
            Db.create_all()
            print("Database Created")
    