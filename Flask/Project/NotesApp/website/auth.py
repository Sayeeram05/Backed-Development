from flask import Blueprint, flash, redirect, render_template, request, url_for
from .models import User,db
from werkzeug.security import generate_password_hash,check_password_hash
from flask_login import login_user,logout_user,current_user,login_required

Auth = Blueprint("Auth",__name__)

@Auth.route('/Login',methods=["GET","POST"])
def Login():
    if current_user.is_authenticated:
        return redirect(url_for("Views.Home"))
    if(request.method == "POST"):
        Email = request.form.get("email")
        Password = request.form.get("password")
        
        user = User.query.filter_by(email=Email).first()
        
        print(user)
        
        if(user):
            if(check_password_hash(user.password,Password)):
                flash(message="Logined successfully",category="success")
                
                login_user(user,remember=True)
                
                return redirect(url_for("Views.Home"))
            else:
                flash(message="Incorrect Password",category="error")
        else:
            flash(message="User Does't Exist",category="error")
        
    return render_template("login.html",user=current_user)

@Auth.route('/Logout')
@login_required
def Logout():
    logout_user()
    return redirect(url_for("Auth.Login"))

@Auth.route('/SignUp',methods=["GET","POST"])
def SignUp():
    if current_user.is_authenticated:
        return redirect(url_for("Views.Home"))
    if request.method == "POST":
        Username = request.form.get("username")
        Email = request.form.get("email")
        Password1 = request.form.get("password1")
        Password2 = request.form.get("password2")
        
        user = User.query.filter_by(email=Email).first()
        
        if(user):
            flash(message="Email is aldready Exist",category="error")
        elif(len(Username) < 5):
            flash(message="Username must greater than 5 Letters",category="error")
        elif(Password1 != Password2):
            flash(message="Password Does't match",category="error")
        elif(len(Password1) < 5):
            flash(message="Password must greater than 5 Letters",category="error")
        else:
            NewUser = User(name=Username,email=Email,password=generate_password_hash(Password1))
            
            db.session.add(NewUser)
            db.session.commit()
            flash(message="Account Created",category="success")
            
            login_user(user,remember=True)
            
            return redirect(url_for("Views.Home"))
            
    return render_template("signup.html",user=current_user)