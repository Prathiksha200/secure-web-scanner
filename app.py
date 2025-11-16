from flask import Flask, render_template, request, redirect, url_for
from scanner import run_basic_scan

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        target = request.form.get("target")
        if not target:
            return redirect(url_for("index"))
        return redirect(url_for("result", target=target))
    return render_template("index.html")

@app.route("/result")
def result():
    target = request.args.get("target")
    if not target:
        return redirect(url_for("index"))
    scan = run_basic_scan(target)
    return render_template("result.html", scan=scan)

if __name__ == "__main__":
    app.run(debug=True)
