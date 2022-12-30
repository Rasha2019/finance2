import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    user_id = session["user_id"]

    stocks = db.execute("SELECT symbol, name, price, SUM(shares) as totalShares FROM transactions WHERE user_id = ? GROUP BY symbol", user_id)
    cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]
    total = cash

    for stock in stocks:
        total += stock["price"] * stock["totalShares"]


    return render_template("index.html", stocks=stocks, cash=cash, usd=usd, total=total)

@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
        # send GET requests to the buy form
    if request.method == "GET":
        return render_template("buy.html")

    if request.method == "POST":
        symbol = request.form.get("symbol").upper()
        item = lookup(symbol)

        if not symbol:
            return apology("Please enter a symbol!")
        elif not item:
            return apology("Invalid symbol!")
        try:
            shares = int(request.form.get("shares"))
        except:
            return apology("Shares must be an integer!")
        if shares <= 0 :
            return apology("Shares must be positive number!")
        user_id = session["user_id"]
        cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]

        item_name = item["name"]
        item_price = item["price"]
        total_price = item_price * shares

        if cash < total_price:
            return apology("Not enough cash!")
        else:
            db.execute("INSERT INTO transactions (user_id, name, shares, price,type, symbol) VALUES (?, ?, ?, ?, ?, ?)",
            user_id, item_name, shares, item_price, 'buy', symbol )
            db.execute("UPDATE users SET cash = ? WHERE id = ?", cash - total_price , user_id)

        flash("Successfully bought!")
        return redirect('/')






@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    user_id = session["user_id"]
    transactions = db.execute("SELECT type, symbol, price, shares, time FROM transactions WHERE user_id = ? ", user_id)
    return render_template("history.html", transactions=transactions, usd=usd )

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 400)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "GET":
        return render_template("quote.html")

    if request.method == "POST":
        quote = lookup(request.form.get("symbol"))

        if quote == None:
            return apology("Please enter valid symbol", 400)
        else:
            symbol = quote.get("symbol")
            price = quote.get("price")
            return render_template("result.html", symbol=symbol, price=usd(price))


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":


        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("Missing username!", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("Missing password!", 400)

        # Ensure password equals condirmation password submitted
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("Passwords don't match!", 400)

        else:
            # Ensure username doesn't exist already in database
            if len(db.execute("SELECT * FROM users WHERE username = :username", username=request.form.get("username"))) == 0:
                # hash the password
                pwdhash = generate_password_hash(request.form.get("password"))
                # insert user to the database
                uid = db.execute("INSERT INTO users (username, hash) VALUES(:username, :hash)",
                                 username=request.form.get("username"), hash=pwdhash)
                session["user_id"] = uid
                # Redirect user to home page
                flash("Registered successfully!")
                return redirect("/")
            else:
                return apology("Please choose another username!", 400)

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        user_id = session["user_id"]
        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))

        if shares <= 0 :
            return apology("Shares must be a positive number!")

        item_price = lookup(symbol)["price"]
        item_name = lookup(symbol)["name"]
        price = shares * item_price


        shares_owned = db.execute("SELECT shares FROM transactions WHERE user_id = ? AND symbol = ? GROUP BY symbol", user_id, symbol)[0]["shares"]
        if shares_owned < shares:
            return apology("Not enough shares!")
        current_cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]
        db.execute("UPDATE users SET cash = ? WHERE id = ?", current_cash + price, user_id )
        db.execute("INSERT INTO transactions(user_id, name, shares, price, type, symbol)VALUES (?,?,?,?,?,?)",
        user_id, item_name, -shares, item_price, 'sell', symbol)
        return redirect('/')
    else:
        user_id = session["user_id"]
        symbols = db.execute("SELECT symbol FROM transactions WHERE user_id = ? GROUP BY symbol", user_id  )
        return render_template("sell.html", symbols=symbols)

@app.route("/password", methods=["GET", "POST"])
@login_required
def password():
    """Allows the user to change their password"""

    user_id = session["user_id"]

    if request.method == "POST":
        old_password = request.form.get("old_password")
        new_password = request.form.get("new_password")
        confirmation = request.form.get("confirmation")
        current_password = db.execute("SELECT hash FROM users WHERE id = ?", user_id)

        # Check for valid user input
        if not old_password:
            return apology("Please enter your Old Password!")
        elif not check_password_hash(current_password[0]["hash"], request.form.get("old_password")):
            return apology("Incorrect password!")
        elif not new_password:
            return apology("Please enter a New Password!")
        elif not confirmation:
            return apology("Please confirm your New Password!")
        elif new_password != confirmation:
            return apology("Passwords must match!")

        hash = generate_password_hash(new_password)

        # Insert new password into db
        db.execute("UPDATE users SET hash = ? WHERE id = ?", hash, user_id)
        return redirect("/")

    else:
        return render_template("password.html")

