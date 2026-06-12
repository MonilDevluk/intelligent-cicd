from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route("/product")
def product():
    name = request.args.get("name", "")
    price = request.args.get("price", "0")
    return render_template_string("<h2>" + name + "</h2><p>Price: $" + price + "</p>")

@app.route("/tag")
def tag():
    tag_name = request.args.get("tag", "")
    return render_template_string("<span class='tag'>" + tag_name + "</span>")
