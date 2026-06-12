from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route("/invoice")
def invoice():
    customer = request.args.get("customer", "")
    amount = request.args.get("amount", "0")
    return render_template_string("<h3>Invoice for " + customer + "</h3><p>Amount: " + amount + "</p>")

@app.route("/notification")
def notification():
    msg = request.args.get("msg", "")
    level = request.args.get("level", "info")
    return render_template_string("<div class='" + level + "'>" + msg + "</div>")
