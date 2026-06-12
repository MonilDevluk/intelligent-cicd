from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route("/search")
def search():
    query = request.args.get("q", "")
    return render_template_string("<h1>Results for: " + query + "</h1>")

@app.route("/profile")
def profile():
    username = request.args.get("name", "")
    html = f"<div>Welcome {username}</div>"
    return render_template_string(html)
