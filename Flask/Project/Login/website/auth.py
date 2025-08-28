from flask import Blueprint, flash, redirect, render_template, request, session, url_for
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
    return redirect(url_for("auth.login"))


@auth.route("/forgot-password/send-otp",methods=["GET","POST"])
def sendOtp():
    if(current_user.is_authenticated):
        flash("You are already logged in.", "error")
        return redirect(url_for("view.home"))
    
    if(request.method == "POST"):
        email = request.form.get("email")
        
        user = User.query.filter_by(email=email).first()
        print(user)
        
        if(user):
            session["email"] = email
            flash("OTP sent to your email.", "success")
            
            return redirect(url_for("auth.verifyOtp"))
        else:
            flash("OTP Verification : Invalid Email","error") 
            
    return render_template("sendOtp.html",user=None)

@auth.route("/forgot-password/verify-otp",methods=["GET","POST"])

def verifyOtp():
    if "email" not in session:
        flash("Access denied. Please start the process from the beginning.", "error")
        return redirect(url_for("auth.sendOtp"))
    if(request.method == "GET"):
        return render_template("verifyOtp.html",user=None)
    if(request.method == "POST"):
        email = session.get("email")
        otp = request.form.get("otp")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")
        
        user = User.query.filter_by(email=email).first()
        
        if(otp == "12345"):
            if(password == confirm_password):
                if(len(password) >= 5):
                    
                    user.password = generate_password_hash(password=password)
                    db.session.commit()
                    session.pop("email",None) 
                    flash("Password updated successfully.", "success")
                    return redirect(url_for("auth.login"))
                else:
                    flash("OTP Verification : Password min length 5","error")
            else:
                flash("OTP Verification : Password Does't Match","error")
        else:
            flash("OTP Verification : OTP Does't Match","error")
        
        return redirect(url_for("auth.sendOtp"))