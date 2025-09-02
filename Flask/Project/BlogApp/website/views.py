from flask import Blueprint, render_template

Views = Blueprint("Views",__name__)

@Views.route("/")
def Home():
    return render_template("home.html")