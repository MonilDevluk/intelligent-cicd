from flask import Flask, request, render_template_string, make_response

app = Flask(__name__)

@app.route("/greet")
def greet():
    name = request.args.get("name", "stranger")
    return render_template_string("<h1>Hello " + name + "!</h1>")

@app.route("/comment")
def comment():
    text = request.form.get("comment", "")
    return render_template_string("<p>" + text + "</p>")
