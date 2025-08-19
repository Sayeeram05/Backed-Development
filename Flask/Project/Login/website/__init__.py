from flask import Flask

def createApp():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "dfsghdfhbdfgjnhfgnsdafvgs"
    
    from .auth import auth
    from .view import view
    
    app.register_blueprint(auth,url_prefix="/")
    app.register_blueprint(view,url_prefix="/")
    
    return app

