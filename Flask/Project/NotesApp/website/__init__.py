import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

print("Website")
db = SQLAlchemy()
dbName = "Database.db"

def CreateApp():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "qwkdbewkfjbcswehgbvshjvbsd"
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{dbName}"
    db.init_app(app)
    
    from .auth import Auth
    from .views import Views
    from .models import User
    
    CreateDatabase(app)
    
    app.register_blueprint(Auth, url_prefix="/")
    app.register_blueprint(Views, url_prefix="/")
    
    login_manager = LoginManager()
    login_manager.login_view = "Auth.Login"
    login_manager.init_app(app)
    
    @login_manager.user_loader
    def lode_user(id):
        return User.query.get(int(id))

    return app

def CreateDatabase(app):
    if not os.path.exists(dbName):  # <-- only check "Database.db"
        with app.app_context():      # <-- required
            db.create_all()
            print("Created Database")
