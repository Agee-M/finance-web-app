import os

from cs50 import SQL
from datetime import datetime
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


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


    # Get user and cash
    temp = db.execute('SELECT username, cash FROM users WHERE id = ?', session['user_id'])
    user = {'name': temp[0]['username'], 'cash': usd(temp[0]['cash'])}

    # No holdings -> Return default table
    if not db.execute('SELECT * FROM holdings WHERE user_id = ?', session['user_id']):
        stock_info = []
        total_worth = usd(0)
        return render_template('index.html', stock=stock_info, total=total_worth, user=user)

    # Gets all unique symbol info from database
    stocks = db.execute(
        'SELECT holdings.stock AS stock, holdings.share AS share, purchases.bought AS bought FROM holdings JOIN purchases ON holdings.stock = purchases.stock WHERE holdings.user_id = ? GROUP BY holdings.stock', session['user_id'])

    # Parses info to dict
    total_worth = 0
    stock_info = []
    for stock in stocks:

        # Parse: Current symbol, current price, total shares, value of shares
        curr_stock = lookup(stock['stock'])
        stock_info.append({
            'symbol': curr_stock['symbol'],
            'buy': float(stock['bought']),
            'price': usd(float(curr_stock['price'])),
            'shares': int(stock['share']),
            'total_val': usd(float(curr_stock['price']) * float(stock['share'])),
        })

        print(stock_info)

        # Add up all shares
        total_worth += float(curr_stock['price']) * float(stock['share'])

    # Value sum of all shares
    total_worth = usd(total_worth)

    return render_template('index.html', stock=stock_info, total=total_worth, user=user)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == 'POST':

        # Validate inputs
        stock = lookup(request.form.get('symbol'))
        shares = request.form.get('shares')
            # Numeric values

        try:
            int(shares)
        except ValueError:
            return apology('Input numeric value', 400)
            # Empty and negative values
        if not stock:
            return apology('Input stock symbol', 400)
        elif not shares:
            return apology('Input number of shares', 400)
        elif int(shares) <= 0:
            return apology('Input positive number of shares', 400)

        # Gets user balance (string)
        user_cash = db.execute('SELECT cash FROM users WHERE id = ?', session['user_id'])

        # Casts all string values to int
        shares = int(shares)
        user_cash = int(user_cash[0]['cash'])

        # Get cost of transaction
        cost = float(stock['price']) * shares

        # Pocket watching
        balance = user_cash - cost
        if balance < 0:
            return apology('You broke my guy', 400)

        # Insert purchase
        db.execute('INSERT INTO purchases (user_id, date, stock, share, bought) VALUES (?, ?, ?, ?, ?)',
                   session['user_id'], datetime.now(), stock['symbol'], shares, float(stock['price']))

        # Update holdings
        # (Stock doesn't exist)
        if not db.execute('SELECT stock FROM holdings WHERE stock = ? AND user_id = ?', stock['symbol'], session['user_id']):
            db.execute('INSERT INTO holdings (user_id, stock, share) VALUES (?, ?, ?)',
                       session['user_id'], stock['symbol'], shares)
            # (Stock exists)
        else:
            db.execute('UPDATE holdings SET share = (share + ?) WHERE stock = ? AND user_id = ?',
                       shares, stock['symbol'], session['user_id'])

        # Update balance
        db.execute('UPDATE users SET cash = ? WHERE id = ?', balance, session['user_id'])


        flash(f"Bought {shares} of {stock['symbol']} for {usd(float(stock['price']))}")

        return redirect('/')
    else:
        return render_template('buy.html')


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    history = db.execute('SELECT purchase_id, NULL AS sale_id, stock, date, SUM(share) AS share, bought AS price FROM purchases WHERE user_id = ? GROUP BY purchase_id UNION ALL SELECT NULL, sale_id, stock, date, SUM(share) AS share, sold FROM sales WHERE user_id = ? GROUP BY sale_id ORDER BY date DESC',
                         session['user_id'], session['user_id'])
    return render_template('history.html', history=history)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

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

    if request.method == 'POST':

        stock = lookup(request.form.get('symbol'))
        if not request.form.get('symbol'):
            return apology('Input symbol', 400)
        elif not stock:
            return apology('Invalid symbol', 400)
        return render_template('quoted.html', symbol=stock, price=usd(stock["price"]))
    else:
        return render_template('quote.html')


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    if request.method == 'POST':

        # Validate username
        username = request.form.get('username')
        if not username:
            return apology('Register a username', 400)

        # Validate password
        password = request.form.get('password')
        if not password:
            return apology('Register a password', 400)

        # Confirm password
        confirmation = request.form.get('confirmation')
        if not confirmation:
            return apology('Passwords do not match', 400)

        # Check if username is in database
        if password == confirmation:
            try:
                db.execute('INSERT INTO users(username, hash) VALUES(?, ?)',
                           username, generate_password_hash(password))
                return render_template('login.html')
            except ValueError:
                return apology('Username taken', 400)
        else:
            return apology('Match passwords', 400)
    else:
        return render_template('register.html')


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    # Check for holdings data
    if not db.execute('SELECT * FROM holdings WHERE user_id = ?', session['user_id']):
        return apology('You have nothing to sell', 400)
    else:

        # For current user, get unique Symbols and Shares - GET and POST
        stocks = db.execute(
            'SELECT stock, share, cash FROM holdings JOIN users ON user_id = id WHERE user_id = ? GROUP BY stock', session['user_id'])

    # Check for POST
    if request.method == 'POST':


        # Validate empty input
        symbol = request.form.get('symbol')
        if not symbol:
            return apology('Select a stock', 400)
        shares = request.form.get('shares')

        # Validate numeric input
        try:
            int(shares)
        except ValueError:
            return apology('Input numeric value', 400)

        # Validate empty or negative input
        if not shares or int(shares) < 1:
            return apology('Choose valid amount', 400)

        # Validate incorrect input
        else:
            same = False
            for stock in stocks:
                if symbol == stock['stock']:

                    # Validate # of shares given
                    if int(shares) > int(stock['share']):
                        return apology('Input less shares', 400)
                    same = True
            if not same:
                return apology('Stock does not exist', 400)

        # Get profit (current stock price * shares sold)
        sold = lookup(symbol)
        profit = sold
        profit = float(profit['price'])
        profit *= int(shares)
        total = profit + float(stocks[0]['cash'])

        # Insert new sales data
        db.execute('INSERT INTO sales (user_id, date, stock, share, sold) VALUES (?, ?, ?, ?, ?)',
                   session['user_id'], datetime.now(), symbol, int(shares), usd(float(sold['price'])))

        # Update holdings
        curr_shares = db.execute(
            'SELECT share FROM holdings WHERE stock = ? AND user_id = ?', symbol, session['user_id'])
        curr_shares = curr_shares[0]['share']
        new_shares = int(curr_shares) - int(shares)
        if new_shares == 0:
            db.execute('DELETE FROM holdings WHERE stock = ? AND user_id = ?',
                       symbol, session['user_id'])
        else:
            db.execute('UPDATE holdings SET share = ? where stock = ? AND user_id = ?',
                       new_shares, symbol, session['user_id'])

        # Update user's (cash)
        db.execute('UPDATE users SET cash = ? WHERE id = ?', total, session['user_id'])

        flash(f"Sold {shares} of {symbol} for {usd(float(shares) * float(sold['price']))}")

        return redirect('/')
    else:
        return render_template('sell.html', stocks=stocks)
