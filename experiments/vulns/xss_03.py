from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route("/error")
def error():
    msg = request.args.get("msg", "Unknown error")
    return render_template_string("<div class='error'>" + msg + "</div>")

@app.route("/redirect")
def redirect_page():
    url = request.args.get("url", "/")
    return render_template_string(f"<a href='{url}'>Click here</a>")
