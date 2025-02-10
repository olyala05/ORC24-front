from flask import Flask, render_template
from flask_scss import Scss

app = Flask(__name__)

# Flask-SCSS'i başlat
Scss(app, static_dir='static', asset_dir='assets')

@app.route('/')
def index():
    return render_template("index.html")


@app.route('/login')
def login():
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")

if __name__ == '__main__':
    app.run(debug=True, port=5001)