from flask import Blueprint, render_template

Auth = Blueprint("Auth",__name__)

@Auth.route('/Login')
def Login():
    return render_template("login.html")

@Auth.route('/Logout')
def Logout():
    return render_template("logout.html")

@Auth.route('/SignUp')
def SignUp():
    return render_template("signup.html")