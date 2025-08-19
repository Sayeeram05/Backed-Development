from flask import Blueprint, flash, render_template, request, url_for

view = Blueprint("view",__name__)

@view.route("/")
def home():
    return render_template("home.html")

@view.route("/signup",methods=["GET","POST"])
def signUp():
    if(request.method == "POST"):
        userName = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        confirmPawword = request.form.get("confirmPassword")
        
        if(len(userName) < 5):
            flash("Invalid Username : Minimum Length 5","error")
        elif(password != confirmPawword):
            flash("Invalid Password : Password Does't Match","error")
        elif(len(password) < 5):
            flash("Invalid Password : Minimum Length 5","error")
        else:
            flash("Account Created : Signup Sucess","sucess")
            
    return render_template("signup.html")

@view.route("/login")
def login():
    return render_template("login.html")

@view.route("/logout")
def logout():
    return render_template("login.html")



