from flask import Blueprint, flash, redirect, render_template, request, url_for
from .models import User
from . import db

from werkzeug.security import generate_password_hash,check_password_hash
auth = Blueprint("auth",__name__)


@auth.route("/signup",methods=["GET","POST"])
def signUp():
    if(request.method == "POST"):
        userName = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        confirmPawword = request.form.get("confirmPassword")
        
        user = User.query.filter_by(email=email).first()
        if(user):
            flash("Invalid Email : You Aldready Have Account","error")
        elif(len(userName) < 5):
            flash("Invalid Username : Minimum Length 5","error")
        elif(password != confirmPawword):
            flash("Invalid Password : Password Does't Match","error")
        elif(len(password) < 5):
            flash("Invalid Password : Minimum Length 5","error")
        else:
            newUser = User(userName=userName,email=email,password=generate_password_hash(password))
            db.session.add(newUser)
            db.session.commit()
            
            flash("Account Created : Signup success","success")
            
            return redirect(url_for("view.home"))
            
    return render_template("signup.html")

@auth.route("/login",methods=["GET","POST"])
def login():
    if(request.method == "POST"):
        email = request.form.get("email")
        password = request.form.get("password")
        
        user = User.query.filter_by(email=email).first()
        
        if(user):
            if(check_password_hash(pwhash=user.password,password=password)):
                flash("Login : Login Sucessful","success")
                return redirect(url_for("view.home"))
            else:
                flash("Login : Incorrect Password","error")
        else:
            flash("Login : Invalid Email","error")
    return render_template("login.html")

@auth.route("/logout")
def logout():
    return render_template("login.html")