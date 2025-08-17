from flask import Flask

def CreateApp():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "qwkdbewkfjbcswehgbvshjvbsd"
    
    from .auth import Auth
    from.views import Views
    
    app.register_blueprint(Auth,url_prefix="/")
    app.register_blueprint(Views,url_prefix="/")
    
    
    return app
