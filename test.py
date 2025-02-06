import os
import csv
import time
import random
import threading
from datetime import datetime
import functools
from SmartApi import SmartConnect  # ✅ Ensure the AngelOne Smart API is installed
from data import db  # ✅ Import `db` from `database.py`
from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, session, jsonify
)
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_socketio import SocketIO, emit
from flask_wtf import FlaskForm
from wtforms.validators import DataRequired, Length, NumberRange

from wtforms import (
    StringField, PasswordField, SubmitField,
    IntegerField, FloatField, SelectField, SelectMultipleField  # ✅ Add this!
)

from flask_wtf.csrf import CSRFProtect

import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Fetching credentials from environment variables
API_KEY = os.getenv("API_KEY")
CLIENT_CODE = os.getenv("CLIENT_CODE")
CLIENT_PASSWORD = os.getenv("CLIENT_PASSWORD")
TOTP_SECRET = os.getenv("TOTP_SECRET")

import functools
from flask import redirect, url_for, session, flash

def admin_required(f):
    """
    Decorator to ensure only the Admin can access certain routes.
    Redirects to login if not authenticated.
    """
    @functools.wraps(f)
    def wrap(*args, **kwargs):
        if not session.get("is_admin"):
            flash("Please log in as admin.", "danger")
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return wrap


##############################################################################
# If you use .env, load it:
# from dotenv import load_dotenv
# load_dotenv()
##############################################################################

app = Flask(__name__, template_folder='.')
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY", "MY_SUPER_SECRET_KEY")
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL", "sqlite:///multi_broker_traders.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)
socketio = SocketIO(app, cors_allowed_origins="*")

##############################################################################
# Single Admin Credentials
##############################################################################
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin")
ADMIN_HASH = bcrypt.generate_password_hash(ADMIN_PASSWORD).decode("utf-8")

##############################################################################
# Database Models
##############################################################################
class TradingUser(db.Model):
    """
    A "TradingUser" does NOT log in themselves. The Admin manages them.
    They each have a broker ('angel' or 'shonnay'), an API key, an optional TOTP,
    and a default quantity for trades.
    """
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)


    broker = db.Column(db.String(20), nullable=False)     # angel or shonnay
    api_key = db.Column(db.String(128), nullable=False)   # for "angel" or dummy
    totp_token = db.Column(db.String(64), nullable=True)  # optional
    default_quantity = db.Column(db.Integer, default=1)

    trades = db.relationship("Trade", backref="trading_user", lazy=True)

class Trade(db.Model):
    """
    Represents a single trade (BUY/SELL).
    """
    id = db.Column(db.Integer, primary_key=True)
    symbol = db.Column(db.String(20), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    transaction_type = db.Column(db.String(10), nullable=False)  # BUY or SELL
    price = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    broker_order_id = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # ✅ Track when user was added
    user_id = db.Column(db.Integer, db.ForeignKey('trading_user.id'), nullable=False)




with app.app_context():
    db.create_all()

##############################################################################
# Simulated "Live Price" from Angel
##############################################################################
from SmartApi import SmartConnect
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

API_KEY = os.getenv("API_KEY")
CLIENT_CODE = os.getenv("CLIENT_CODE")
CLIENT_PASSWORD = os.getenv("CLIENT_PASSWORD")
TOTP_SECRET = os.getenv("TOTP_SECRET")

from SmartApi import SmartConnect

def get_symbol_token(symbol):
    """
    Fetch the correct symbol token from AngelOne API.
    """
    obj = SmartConnect(api_key=API_KEY)
    session_data = obj.generateSession(CLIENT_CODE, CLIENT_PASSWORD, TOTP_SECRET)  # ✅ Fix Login
    
    if session_data.get("status") is False:
        print("Error: Invalid AngelOne API credentials!")
        return None

    # Fetch all available symbols
    response = obj.searchScrip("NSE", symbol)  # ✅ Search symbol in NSE

    if response.get("status") == True and response.get("data"):
        return response["data"][0]["symboltoken"]  # ✅ Get first match
    else:
        print(f"Error: Symbol {symbol} not found!")
        return None

def fetch_live_price(symbol):
    """
    Fetch live market price using AngelOne API for any selected symbol.
    """
    obj = SmartConnect(api_key=API_KEY)
    session_data = obj.generateSession(CLIENT_CODE, CLIENT_PASSWORD, TOTP_SECRET)  # ✅ Fix Login

    if session_data.get("status") is False:
        print("Error: Invalid AngelOne API credentials!")
        return None

    symbol_token = get_symbol_token(symbol)  # ✅ Get correct token
    if not symbol_token:
        return None  # ✅ Return None if token is not found

    payload = {
        "exchange": "NSE",
        "tradingsymbol": symbol,
        "symboltoken": symbol_token  # ✅ Use dynamic token
    }
    response = obj.ltpData(payload)

    if response.get("status") == True:
        return response["data"]["ltp"]  # ✅ Extract last traded price
    else:
        return None


@app.route("/fetch_price")
@admin_required
def fetch_price():
    """
    Fetch live price for the selected symbol.
    """
    symbol = request.args.get("symbol", "NIFTY 50")  # Default to NIFTY 50
    live_price = fetch_live_price(symbol)

    if live_price:
        return jsonify({"price": live_price})
    else:
        return jsonify({"error": "Symbol not found"}), 400


##############################################################################
# Admin-Required Decorator
##############################################################################
def admin_required(f):
    @functools.wraps(f)
    def wrap(*args, **kwargs):
        if not session.get("is_admin"):
            flash("Please log in as admin.", "danger")
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return wrap

##############################################################################
# Global flags for auto trade & stop-loss
##############################################################################
auto_trade_flags = {}
stop_loss_flags = {}

##############################################################################
# FORMS
##############################################################################
class AdminLoginForm(FlaskForm):
    username = StringField("Admin Username", validators=[DataRequired()])
    password = PasswordField("Admin Password", validators=[DataRequired()])
    submit = SubmitField("Admin Login")


class RegisterTradingUserForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=2, max=64)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=3)])

    broker = SelectField("Broker", choices=[("angel", "Angel"), ("shonnay", "Shonnay")])
    api_key = StringField("API Key", validators=[DataRequired(), Length(min=5, max=128)])
    totp_token = StringField("TOTP (optional)", validators=[Length(max=64)])
    default_quantity = IntegerField("Default Quantity", validators=[DataRequired(), NumberRange(min=1)])
    submit = SubmitField("Register User")

class PlaceOrderForm(FlaskForm):
    """
    For the Admin to place a manual trade on behalf of a user.
    """
    user_ids = SelectMultipleField("Users", coerce=int)  # Allow multiple users

    symbol = StringField("Symbol", validators=[DataRequired(), Length(min=1, max=20)])
    quantity = IntegerField("Quantity (0 => use default)", default=0)
    transaction_type = SelectField("Type", choices=[("BUY", "Buy"), ("SELL", "Sell")])
    price = FloatField("Price", validators=[DataRequired(), NumberRange(min=0)])
    submit = SubmitField("Place Order")

@app.route("/view_users")
@admin_required
def view_users():
    order = request.args.get("order", "desc")  # Get sort order
    try:
        if hasattr(TradingUser, "created_at"):  # ✅ Ensure column exists
            if order == "asc":
                users = TradingUser.query.order_by(TradingUser.created_at.asc()).all()
            else:
                users = TradingUser.query.order_by(TradingUser.created_at.desc()).all()
        else:
            users = TradingUser.query.all()  # ✅ Safe fallback

        return render_template("view_users.html", users=users)
    
    except Exception as e:
        app.logger.error(f"Error loading users: {str(e)}")
        return "Error loading users.", 500



@app.route("/delete_user/<int:user_id>", methods=["POST"])
@admin_required
def delete_user(user_id):
    """
    Delete a specific user by ID.
    """
    user = TradingUser.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        return jsonify({"success": True, "message": f"User '{user.username}' deleted successfully."}), 200
    else:
        return jsonify({"success": False, "message": "User not found."}), 404



@app.route("/delete_all_users", methods=["POST"])
@admin_required
def delete_all_users():
    """
    Delete all trading users from the database.
    """
    try:
        num_deleted = TradingUser.query.delete()
        db.session.commit()
        flash(f"Deleted {num_deleted} users successfully.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error deleting users: {e}", "danger")

    return redirect(url_for("view_users"))

##############################################################################
# Admin Login / Logout
##############################################################################
from flask import send_from_directory

@app.route('/ramdoot.jpg')
def serve_logo():
    """Serve the logo image directly from the root directory."""
    return send_from_directory('.', 'ramdoot.jpg')

@app.route("/admin_login", methods=["GET", "POST"])
def admin_login():
    """
    Admin Login: If successful, redirect to the home (market dashboard).
    """
    form = AdminLoginForm()
    if form.validate_on_submit():
        if form.username.data == ADMIN_USERNAME and bcrypt.check_password_hash(ADMIN_HASH, form.password.data):
            session["is_admin"] = True
            flash("Welcome, Admin!", "success")
            return redirect(url_for("market_dashboard"))  # ✅ Redirect to the dashboard
        else:
            flash("Invalid admin credentials!", "danger")
            return redirect(url_for("admin_login"))

    return render_template("admin_login.html", form=form)


@app.route("/admin_logout")
@admin_required
def admin_logout():
    session.pop("is_admin", None)
    flash("Admin logged out.", "info")
    return redirect(url_for("admin_login"))

##############################################################################
# Home => redirect to Dashboard if logged in or Admin Login if not
##############################################################################
@app.route("/")
def home():
    """
    Home Route: Redirects Admin to Admin Dashboard if logged in.
    """
    if session.get("is_admin"):
        return redirect(url_for("admin_dashboard"))  # ✅ Redirect to Admin Dashboard
    else:
        return redirect(url_for("admin_login"))  # ✅ Redirect to Login Page

@app.route("/market_dashboard")
@admin_required
def market_dashboard():
    """
    Display live NIFTY price & allow admin to select a symbol.
    """
    return render_template("market_dashboard.html")

@app.route("/option_chain")
@admin_required
def option_chain():
    """
    Display the option chain for the selected symbol.
    """
    symbol = request.args.get("symbol", "NIFTY 50")
    return render_template("option_chain.html", symbol=symbol)

@app.route("/market_trend")
@admin_required
def market_trend():
    """
    Determines whether the market is trending UP or DOWN.
    """
    symbol = request.args.get("symbol", "NIFTY 50")
    live_price = fetch_live_price(symbol)

    if live_price:
        prev_price = fetch_live_price(symbol)  # Get a past price
        trend = "UP" if live_price > prev_price else "DOWN"
        return jsonify({"trend": trend})
    else:
        return jsonify({"error": "Unable to fetch market trend"}), 400


##############################################################################
# Admin Dashboard
##############################################################################
# Routes
@app.route("/admin_dashboard")
@admin_required
def admin_dashboard():
    page = request.args.get('page', 1, type=int)
    per_page = 10  # Adjust as needed
    
    users = TradingUser.query.paginate(page=page, per_page=per_page, error_out=False)
    trades = Trade.query.paginate(page=page, per_page=per_page, error_out=False)

    return render_template(
        "admin_dashboard.html",
        users=users.items,  # ✅ Convert to list instead of pagination object
        trades=trades.items,  # ✅ Same here
        total_users=users.total if users.items else 0,  # ✅ Avoid errors
        total_trades=trades.total if trades.items else 0
    )


##############################################################################
# Register Trading Users (single or bulk)
##############################################################################
@app.route("/register_user", methods=["GET", "POST"])
@admin_required
def register_user():
    form = RegisterTradingUserForm()
    if form.validate_on_submit():
        if TradingUser.query.filter_by(username=form.username.data).first():
            flash("Username already exists!", "danger")
            return redirect(url_for("register_user"))

        hashed_password = bcrypt.generate_password_hash(form.password.data).decode("utf-8")
        new_user = TradingUser(
            username=form.username.data,
            password=hashed_password,
            broker=form.broker.data,
            api_key=form.api_key.data,
            totp_token=form.totp_token.data if form.broker.data == "angel" else None,
            default_quantity=form.default_quantity.data
        )

        db.session.add(new_user)
        db.session.commit()
        flash(f"Registered user '{new_user.username}' successfully.", "success")
        return redirect(url_for("admin_dashboard"))

    return render_template("register_user.html", form=form)


@app.route("/bulk_register", methods=["POST"])
@admin_required
def bulk_register():
    """
    CSV format: username,broker,api_key,totp_token,default_quantity
    """
    file = request.files.get("file")
    if not file or not file.filename.endswith(".csv"):
        flash("Please upload a valid CSV file (.csv).", "danger")
        return redirect(url_for("register_user"))

    try:
        reader = csv.reader(file.stream.read().decode("utf-8").splitlines())
        count = 0
        for row in reader:
            if len(row) < 5:
                continue
            username, broker, api_key, totp_token, def_qty = row
            # skip if user exists
            if TradingUser.query.filter_by(username=username).first():
                continue
            user = TradingUser(
                username=username,
                broker=broker,
                api_key=api_key,
                totp_token=totp_token,
                default_quantity=int(def_qty or 1)
            )
            db.session.add(user)
            count += 1
        db.session.commit()
        flash(f"Bulk registered {count} users.", "success")
    except Exception as e:
        flash(f"Error during bulk register: {e}", "danger")

    return redirect(url_for("register_user"))
def place_order(user, transaction_type, symbol, price, quantity):
    """
    Place an order for AngelOne API for a specific user.
    """
    obj = SmartConnect(api_key=user.api_key)
    session_data = obj.generateSession(user.username, user.password, user.totp_token)

    if session_data.get("status") is False:
        print(f"Error: Invalid API login for {user.username}")
        return None

    symbol_token = get_symbol_token(symbol)
    if not symbol_token:
        return None

    orderparams = {
        "variety": "NORMAL",
        "tradingsymbol": symbol,
        "symboltoken": symbol_token,
        "transactiontype": transaction_type,
        "exchange": "NSE",
        "ordertype": "LIMIT",
        "producttype": "INTRADAY",
        "duration": "DAY",
        "price": price,
        "quantity": quantity
    }
    
    order_response = obj.placeOrder(orderparams)

    if order_response.get("status") == True:
        return order_response["data"]["orderid"]  # ✅ Return Order ID
    else:
        print(f"Error placing order for {user.username}: {order_response}")
        return None

def fetch_option_chain(symbol):
    """
    Fetch the Option Chain for the given symbol using AngelOne API.
    """
    obj = SmartConnect(api_key=API_KEY)
    obj.generateSession(CLIENT_CODE, TOTP_SECRET)

    payload = {
        "exchange": "NFO",  # NSE F&O Segment
        "tradingsymbol": symbol
    }
    
    response = obj.getOptionChain(payload)

    if response.get("status") == True and response.get("data"):
        option_chain = {"CALLS": [], "PUTS": []}
        
        for option in response["data"]:
            option_type = "CALLS" if option["instrumenttype"] == "CE" else "PUTS"
            option_chain[option_type].append({
                "symbol": option["tradingsymbol"],
                "strike": option["strikeprice"],
                "ltp": option["ltp"],
                "expiry": option["expiry"]
            })

        return option_chain
    else:
        return None

@app.route("/option_chain/<symbol>", methods=["GET"])
@admin_required
def option_chain(symbol):
    """
    Fetch and return the Option Chain for a selected symbol.
    """
    option_data = fetch_option_chain(symbol)
    
    if option_data:
        return jsonify(option_data)
    else:
        return jsonify({"error": "Unable to fetch option chain"}), 500

##############################################################################
# Place Orders Page (MANUAL + AUTO + STOP-LOSS)
##############################################################################
@app.route("/place_trade", methods=["POST"])
@admin_required
def place_trade():
    """
    Places a trade (BUY CALL / BUY PUT) for multiple users based on selection.
    """
    data = request.get_json()
    symbol = data.get("symbol")
    trade_type = data.get("type")
    user_ids = data.get("user_ids", [])

    if not symbol or trade_type not in ["CALL", "PUT"] or not user_ids:
        return jsonify({"error": "Invalid trade parameters"}), 400

    # Fetch the latest Option Chain for the selected symbol
    option_chain = fetch_option_chain(symbol)
    
    # Select the best option strike price based on market trend
    if trade_type == "CALL":
        selected_option = option_chain["CALLS"][0]  # Closest ITM Call Option
    else:
        selected_option = option_chain["PUTS"][0]  # Closest ITM Put Option

    placed_orders = []
    failed_orders = []

    # Execute trade for each selected user
    selected_users = TradingUser.query.filter(TradingUser.id.in_(user_ids)).all()

    for user in selected_users:
        qty = user.default_quantity  # Use user's default quantity

        order_id = place_order(
            user=user,
            transaction_type="BUY",
            symbol=selected_option["symbol"],
            price=selected_option["ltp"],
            quantity=qty
        )

        if order_id:
            # Save trade details in database
            new_trade = Trade(
                symbol=selected_option["symbol"],
                quantity=qty,
                transaction_type="BUY",
                price=selected_option["ltp"],
                broker_order_id=order_id,
                user_id=user.id
            )
            db.session.add(new_trade)
            placed_orders.append({"user": user.username, "order_id": order_id})
            
            # Emit new trade event via WebSocket
            socketio.emit('new_trade', {
                "symbol": new_trade.symbol,
                "price": new_trade.price,
                "broker_order_id": new_trade.broker_order_id,
                "username": user.username,
                "broker": user.broker
            }, broadcast=True)
        else:
            failed_orders.append(user.username)

    db.session.commit()  # ✅ Commit all successful orders

    if placed_orders:
        return jsonify({"success": True, "placed_orders": placed_orders, "failed_orders": failed_orders})
    else:
        return jsonify({"error": "Failed to place orders"}), 500


##############################################################################
# View All Trades
##############################################################################
@app.route("/trades")
@admin_required
def view_trades():
    trades = Trade.query.order_by(Trade.timestamp.desc()).all()
    return render_template("trades.html", trades=trades)

##############################################################################
# Live Chart
##############################################################################
@app.route("/chart")
@admin_required
def chart():
    return render_template("chart.html")

@socketio.on("request_trades")
def handle_request_trades():
    all_trades = Trade.query.order_by(Trade.id.asc()).all()
    data = []
    for t in all_trades:
        data.append({
            "symbol": t.symbol,
            "price": t.price,
            "broker_order_id": t.broker_order_id,
            "username": t.trading_user.username,
            "broker": t.trading_user.broker
        })
    emit("initial_trades", data)

##############################################################################
# AUTO TRADE & STOP-LOSS API (for admin to config any user)
##############################################################################
@app.route("/api/manual_trade", methods=["POST"])
@admin_required
def api_manual_trade():
    """
    Place a manual trade for a user.
    JSON body example:
    {
      "user_id": 2,
      "symbol": "INFY",
      "transaction_type": "BUY"/"SELL",
      "price": 1950,
      "exchange": "NSE"
    }
    """
    data = request.get_json()
    user_id = data.get("user_id")
    user = TradingUser.query.get(user_id)
    if not user:
        return jsonify({"success": False, "message": "Invalid user_id"}), 400

    # Fetch user-specific details
    quantity = user.default_quantity
    broker = user.broker
    api_key = user.api_key
    totp_token = user.totp_token

    # Get trade details
    symbol = data.get("symbol")
    transaction_type = data.get("transaction_type")
    price = float(data.get("price", 0))
    exchange = data.get("exchange", "NSE")  # Default to NSE

    if not symbol or not transaction_type or price <= 0:
        return jsonify({"success": False, "message": "Missing or invalid trade details."}), 400

def place_order(user, transaction_type, symbol, price, quantity):
    """ Place an order for AngelOne or Shonnay """
    if user.broker == "angel":
        obj = SmartConnect(api_key=user.api_key)
        obj.generateSession(user.username, user.totp_token)
        orderparams = {
            "variety": "NORMAL",
            "tradingsymbol": symbol,
            "symboltoken": "1234",
            "transactiontype": transaction_type,
            "exchange": "NSE",
            "ordertype": "LIMIT",
            "producttype": "INTRADAY",
            "duration": "DAY",
            "price": price,
            "quantity": quantity
        }
        return obj.placeOrder(orderparams)

    elif user.broker == "shonnay":
        return f"SH-{int(time.time())}"  # Simulated Shonnay Order ID

    return None
    
@app.route("/live_chart", methods=["GET"])
@admin_required
def live_chart():
    """
    Display a live market chart for a selected trading symbol and exchange.
    Defaults to 'INFY' on 'NSE' if no parameters are provided.
    """
    # Fetch symbol and exchange from query parameters or use defaults
    tradingsymbol = request.args.get("tradingsymbol", "INFY")  # Default: INFY
    exchange = request.args.get("exchange", "NSE")            # Default: NSE
    return render_template("live_chart.html", tradingsymbol=tradingsymbol, exchange=exchange)


@app.route("/auto_trade_buy", methods=["GET"])
@admin_required
def auto_trade_buy():
    """
    Render Auto Trade (BUY) with Stop-Loss page when BUY button is clicked.
    """
    return render_template("auto_trade_buy.html")  # Ensure this template exists

@app.route("/auto_trade_sell", methods=["GET"])
@admin_required
def auto_trade_sell():
    """
    Render Auto Trade (SELL) with Stop-Loss page when SELL button is clicked.
    """
    return render_template("auto_trade_sell.html")  # Ensure this template exists



@app.route("/api/auto_trade", methods=["POST"])
@admin_required
def api_auto_trade():
    """
    Starts auto trading for a user with required stop-loss configuration.
    """
    data = request.get_json()
    user_ids = data.get("user_ids", [])
    selected_users = TradingUser.query.filter(TradingUser.id.in_(user_ids)).all()

    if not selected_users:
        return jsonify({"success": False, "message": "No valid users selected."}), 400

    # Validate trade and stop-loss details
    symbol = data.get("symbol")
    condition = data.get("condition")
    basis = data.get("basis")
    threshold_value = float(data.get("threshold_value", 0))
    reference_price = float(data.get("reference_price", 0))
    stop_loss_type = data.get("stop_loss_type")
    stop_loss_value = data.get("stop_loss_value")

    if not symbol or not condition or not basis or not stop_loss_type or stop_loss_value is None:
        return jsonify({"success": False, "message": "Missing required fields."}), 400

    # Start Auto Trading for Each User
    for user in selected_users:
        if auto_trade_flags.get(user.id, False):
            continue  # Skip if already running

        auto_trade_flags[user.id] = True

        threading.Thread(
            target=monitor_auto_trade, 
            args=(user, symbol, condition, basis, threshold_value, stop_loss_type, stop_loss_value, user.default_quantity),
            daemon=True
        ).start()

    return jsonify({"success": True, "message": "Auto trade started with stop-loss."}), 200

def monitor_auto_trade(user, symbol, condition, basis, threshold_value, stop_loss_type, stop_loss_value, qty, points_condition):
    """
    Monitors live market price, applies the user-defined strategy, 
    executes a BUY order, and activates stop-loss monitoring.
    """
    while True:
        live_price = fetch_live_price(symbol, user.broker)
        if live_price is None:
            time.sleep(5)
            continue

        # ✅ Get Market Trend for CALL/PUT Decision
        expected_trend = get_trend(symbol, user.broker)

        # ✅ Apply Strategy Before Placing BUY Order
        triggered = False
        if condition == "Condition 1" and basis == "fixed" and live_price >= threshold_value:
            triggered = True
        elif condition == "Condition 2" and basis == "fixed" and live_price > threshold_value:
            triggered = True

        if triggered:
            try:
                # ✅ Step 1: Select Option (CALL/PUT)
                option_type = "CALL" if expected_trend == "UP" else "PUT"

                # ✅ Step 2: Fetch Option Chain Data
                options_chain = fetch_option_chain(symbol, user.broker)

                # ✅ Step 3: Select Best Strike Price
                selected_strike = select_best_strike_price(options_chain, strategy="ATM")

                # ✅ Step 4: Get Live Price of Selected Option
                option_live_price = fetch_live_price(selected_strike, user.broker)
                if option_live_price is None:
                    print(f"Error fetching price for {selected_strike}")
                    return

                entry_price = option_live_price

                # ✅ Step 5: Calculate Stop-Loss Before Placing BUY Order
                if stop_loss_type == "percentage":
                    stop_loss_price = entry_price - (entry_price * (stop_loss_value / 100))
                elif stop_loss_type == "points":
                    stop_loss_price = entry_price - stop_loss_value
                else:
                    stop_loss_price = stop_loss_value  # Fixed SL

                # ✅ Step 6: Ensure SELL Order is Configured Before BUY
                print(f"Pre-configuring SELL Order at {stop_loss_price} before executing BUY...")

                # ✅ Step 7: Place BUY Order (Auto Execution)
                order_id = place_order(user, "BUY", selected_strike, entry_price, qty, option_type)
                print(f"BUY ORDER PLACED: {order_id} for {selected_strike} at {entry_price}")

                # ✅ Step 8: Activate Stop-Loss & Auto-Sell
                monitor_stop_loss(user, selected_strike, entry_price, stop_loss_type, stop_loss_value, qty, points_condition)

                break  # ✅ Stop monitoring after placing order
            except Exception as e:
                print(f"Error placing BUY order: {e}")
                break

        time.sleep(5)  # ✅ Keep checking until condition is met

def monitor_stop_loss(user, symbol, entry_price, sl_type, sl_value, qty, points_condition):
    """
    Monitors live market price and dynamically updates stop-loss.
    Executes SELL order automatically when conditions are met.
    """
    base = entry_price
    highest = entry_price

    while True:
        live_price = fetch_live_price(symbol, user.broker)
        if live_price is None:
            time.sleep(5)
            continue

        # ✅ Update Highest Price If Market Moves Up
        if live_price > highest:
            highest = live_price  

        # ✅ Adjust Base Price If Negative Points Condition (-0.2, -2) is Set
        if points_condition < 0 and live_price < base:
            base = live_price  

        # ✅ Stop-Loss Calculation Based on Type
        if sl_type == "percentage":
            current_sl = base + (highest - base) * (sl_value / 100.0)

        elif sl_type == "points":
            current_sl = highest - sl_value

        elif sl_type == "fixed":
            current_sl = float(sl_value)

        else:
            current_sl = base  # Default SL

        print(f"Updated Stop-Loss: {current_sl}, Live Price: {live_price}")

        # ✅ If Live Price Hits Stop-Loss, Execute Auto-Sell
        if live_price <= current_sl:
            order_id = place_order(user, "SELL", symbol, live_price, qty)
            print(f"STOP-LOSS HIT! AUTO SELL ORDER EXECUTED: {order_id}")
            break

        time.sleep(5)



##############################################################################
# MAIN
##############################################################################
if __name__ == "__main__":
    socketio.run(app, debug=True)
