from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route("/bio")
def bio():
    user_bio = request.args.get("bio", "")
    return render_template_string("<div class='bio'>" + user_bio + "</div>")

@app.route("/title")
def title():
    page_title = request.args.get("title", "Home")
    return render_template_string("<title>" + page_title + "</title><h1>" + page_title + "</h1>")
