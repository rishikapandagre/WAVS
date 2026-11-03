
from flask import Flask, request

app = Flask(__name__)


@app.route("/")
def home():
    return """
    <html>
        <head><title>WAVS Test Website</title></head>
        <body>
            <h1>Welcome to WAVS Test Website</h1>

            <h2>Search Form</h2>
            <form action="/search" method="GET">
                <input name="q" placeholder="Search here">
                <button type="submit">Search</button>
            </form>

            <h2>Login Form</h2>
            <form action="/login" method="POST">
                <input name="username" placeholder="Username">
                <input name="password" type="password" placeholder="Password">
                <button type="submit">Login</button>
            </form>

            <a href="/about">About Page</a>
        </body>
    </html>
    """


@app.route("/search")
def search():
    query = request.args.get("q", "")
    return f"<h1>Search results: {query}</h1>"


@app.route("/login", methods=["GET", "POST"])
def login():
    return "<h1>Login page</h1>"


@app.route("/about")
def about():
    return "<h1>About WAVS</h1>"


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=False)
