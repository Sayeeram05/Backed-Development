from calendar import c
import os
from flask import Flask
from flask_login import LoginManager

from app.auth import login
from .config import Secret_key
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
dbName = "database.db"

def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = Secret_key
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{dbName}"

    db.init_app(app)
    
    from .views import views
    from .auth import auth
    from .admin import admin
    
    app.register_blueprint(views, url_prefix='/')
    app.register_blueprint(auth, url_prefix='/auth')
    app.register_blueprint(admin, url_prefix='/admin')
    
    from .models import User
    
    create_database(app)
    
    
    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)
    
    @login_manager.user_loader
    def load_user(id):
        return User.query.get(int(id))

    return app

def create_database(app):
    path = os.path.join("instance",dbName)
    print(path)
    if not os.path.exists(path):
        with app.app_context():
            db.create_all()
        print("Database created")
    else:
        print("Database exists")