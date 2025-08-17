from flask import Flask, request


app = Flask(__name__)


@app.route("/")
def index():
    return("Hello World")

@app.route("/Next/")
def Fun2():
    return("<h1>Hello World</h1>")

@app.route("/Sum/<int:num1>/<int:num2>/")
def Sum(num1,num2):
    return(f"{num1} + {num2} = {num1+num2}")

@app.route("/handle_parameters/")
def Fun3():
    return(str(request.args))

@app.route("/handle_parameters/2/")
def Fun4():
    if("name" in request.args.keys()):
        name = request.args.get("name")
        return(f"Name : {name}")
    else:
        return(f"Invalid Name")


@app.route("/methods/",methods=["GET","POST"])
def Fun5():
    if(request.method == "POST"):
        return("Post Method")
    elif(request.method == "GET"):
        return("Get Method")


def Functio
    




if(__name__ == "__main__"):
    app.run(debug=True)
