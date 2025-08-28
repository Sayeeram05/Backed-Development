from flask import Flask, flash, render_template

app = Flask(__name__)

app.config["SECRET_KEY"] = "DSAFVSADF"

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/flash")
def flashmessage():
    for i in range(10):
        flash(f"Message {i}")
    return render_template("home.html")





app.run(debug=True)