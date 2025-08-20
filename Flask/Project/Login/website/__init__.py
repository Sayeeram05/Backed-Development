import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
dbName = "database.db"


def createApp():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "dfsghdfhbdfgjnhfgnsdafvgs"
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{dbName}"
    db.init_app(app)
    
    from .auth import auth
    from .view import view
    
    app.register_blueprint(auth,url_prefix="/")
    app.register_blueprint(view,url_prefix="/")
    
    createDatabase(app)
    
    return app

def createDatabase(app):
    path = os.path.join("instance",dbName)
    if not (os.path.exists(path)):
        with app.app_context(): # Current active app
            db.create_all()

            print("\nDataBase Created\n")
    