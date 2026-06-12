from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route("/news")
def news():
    headline = request.args.get("headline", "")
    author = request.args.get("author", "Unknown")
    return render_template_string("<h2>" + headline + "</h2><p>By " + author + "</p>")

@app.route("/feedback")
def feedback():
    message = request.form.get("message", "")
    return render_template_string("<blockquote>" + message + "</blockquote>")
