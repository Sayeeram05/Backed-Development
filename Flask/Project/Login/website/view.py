from flask import Blueprint, render_template, url_for

view = Blueprint("view",__name__)

@view.route("/")
def home():
    return render_template("home.html")





