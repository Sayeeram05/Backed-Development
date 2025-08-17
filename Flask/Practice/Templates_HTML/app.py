from flask import Flask,render_template


app = Flask(__name__,template_folder="templates")

@app.route("/")
def index():
    Name = "Sayeeram"
    
    List = [1,2,3,4,5,6]
    return render_template("index.html",Name=Name,List = List)

@app.route("/A/")
def Fun1():
    return render_template("inherited.html")

@app.route("/Filter/")
def Fun2():
    return render_template("inherited.html",Name="Sayeeram")


@app.template_filter("reverse")
def reverse(s):
    return s[::-1]

@app.template_filter('repeat')
def repeat(s,times=2):
    return (s+" ")*times
    



if(__name__ == "__main__"):
    app.run(debug=True)