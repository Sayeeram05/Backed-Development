from flask import Blueprint, flash, render_template, request, url_for
from .model import User
from werkzeug.security import generate_password_hash
from . import Db

Views = Blueprint("Views",__name__)

@Views.route("/")
def Home():
    return render_template("home.html")

@Views.route("/add-user",methods=["GET","POST"])
def AddUser():
    if(request.method == "POST"):
        Username = request.form.get("name")
        Age = int(request.form.get("age"))
        Gender = request.form.get("gender")
        Password = request.form.get("password")
        ConfirmPassword = request.form.get("confirm_password")
        
        print(Username,Age,Gender,Password,ConfirmPassword)
        if(len(Username) < 5):
            flash("Add User : Username min length - 5",category="Error")
        elif(Age < 0 or Age > 150):
            flash("Add User : Invalid Age",category="Error")
        elif(len(Password) < 5):
            flash("Add User : Password min length - 5",category="Error")
        elif(Password != ConfirmPassword):
            flash("Add User : Password Does't Match",category="Error")
        else:
            NewUser = User(Username = Username, Age=Age, Gender=Gender, Password=generate_password_hash(password=Password))
            
            Db.session.add(NewUser)
            Db.session.commit()
            
            flash("Add User : Success",category="Success")
        
    return render_template("addUser.html")
    # return url_for("home.html")

@Views.route("/view-user")
def ViewUser():
    return render_template("viewUser.html")
    # return url_for("home.html")

@Views.route("/delete-user")
def DeleteUser():
    return render_template("deleteUser.html")
    # return url_for("home.html")