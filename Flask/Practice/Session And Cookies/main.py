from urllib import response
from flask import Flask, make_response, redirect, render_template, request, session, url_for

app = Flask(__name__)

app.config["SECRET_KEY"] = "sdvsdvvs"


@app.route("/")
def home():
    return render_template("home.html",message="HOME Page")

@app.route("/add-session")
def add():
    session["name"] = "Sai"
    session["id"] = "1467"
    return render_template("home.html",message="Add Sesion")

@app.route("/get-session")
def get():
    if("name" in session.keys() and "id" in session.keys()):
        name = session["name"]
        id = session["id"]
        return render_template("home.html",message=f"Name:{name}      id:{id}")
    return render_template("home.html",message="Name:None     id:None")

@app.route("/delete-session")
def delete():
    if("name" in session.keys() and "id" in session.keys()):
        # session.pop("name")
        # session.pop("id")
        # or
        session.clear()
        return render_template("home.html",message=f"Deleted Session")
    return render_template("home.html",message="Name:None     id:None")


@app.route("/set-cookies")
def setcookies():
    responce = make_response(render_template("home.html",message="Set Cookies"))
    responce.set_cookie("User","Sai")
    return responce

@app.route("/get-cookies")
def getcookies():
    print(request.cookies)
    if("User" in request.cookies):
        user = request.cookies["User"]
        return render_template("home.html",message=f"Cookies : {user}")
    return render_template("home.html",message="Get Cookies")

@app.route("/delete-cookies")
def deletecookies():
    if("User" in request.cookies):
        response = make_response(render_template("home.html",message="Delete Cookies"))
        response.set_cookie("User",expires=0)
        return response
    return render_template("home.html",message="User : None")


        
app.run(debug=True)