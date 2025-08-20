from flask import Blueprint, flash, redirect, render_template, request, url_for
from .models import User
from . import db
from flask_login import login_user,logout_user,login_required,current_user
from werkzeug.security import generate_password_hash,check_password_hash
auth = Blueprint("auth",__name__)


@auth.route("/signup",methods=["GET","POST"])
def signUp():
    if(current_user.is_authenticated):
        return redirect(url_for("view.home"))
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
            
            login_user(user=user,remember=False)
            
            flash("Account Created : Signup success","success")
            
            return redirect(url_for("view.home"))
            
    return render_template("signup.html",user=current_user)

@auth.route("/login",methods=["GET","POST"])
def login():
    if(current_user.is_authenticated):
        return redirect(url_for("view.home"))
    if(request.method == "POST"):
        email = request.form.get("email")
        password = request.form.get("password")
        
        user = User.query.filter_by(email=email).first()
        
        if(user):
            if(check_password_hash(pwhash=user.password,password=password)):
                flash("Login : Login Successful","success")
                
                login_user(user=user,remember=False)

                return redirect(url_for("view.home"))
            else:
                flash("Login : Incorrect Password","error")
        else:
            flash("Login : Invalid Email","error")
    return render_template("login.html",user=current_user)

@auth.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logout : Successful","success")
    return render_template("login.html",user=current_user)

@auth.route("/forget-password")
@login_required
def forgetPassoword():
    pass