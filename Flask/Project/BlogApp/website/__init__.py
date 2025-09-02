from flask import Flask


def CreateApp():
    app = Flask(__name__)
    
    app.config["SECRET_KEY"] = "SSWRGFWRE"
    
    from .views import Views
    
    app.register_blueprint(Views,url_prefix="/")
    
    return app
    