import os
import csv
import time
import threading
import functools
from datetime import datetime

from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, session, jsonify, send_from_directory
)
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_socketio import SocketIO, emit
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import (
    StringField, PasswordField, SubmitField,
    IntegerField, FloatField, SelectField, SelectMultipleField
)
from wtforms.validators import DataRequired, Length, NumberRange

# AngelOne SmartAPI
from SmartApi import SmartConnect

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

##############################################################################
# 1. Environment Variables (AngelOne Credentials + Admin)
##############################################################################
API_KEY = os.getenv("API_KEY")
CLIENT_CODE = os.getenv("CLIENT_CODE")
CLIENT_PASSWORD = os.getenv("CLIENT_PASSWORD")
TOTP_SECRET = os.getenv("TOTP_SECRET")

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin")

##############################################################################
# 2. Flask & SQLAlchemy
##############################################################################
app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "MY_SUPER_SECRET_KEY")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///multi_broker_traders.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Create hashed admin password
ADMIN_HASH = bcrypt.generate_password_hash(ADMIN_PASSWORD).decode("utf-8")

##############################################################################
# 3. Database Models
##############################################################################
class TradingUser(db.Model):
    """
    Represents a single "trading" user (managed by the admin).
    """
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)

    broker = db.Column(db.String(20), nullable=False)       # e.g. 'angel'
    api_key = db.Column(db.String(128), nullable=False)     # user-specific
    totp_token = db.Column(db.String(64), nullable=True)    # optional TOTP
    default_quantity = db.Column(db.Integer, default=1)

    trades = db.relationship("Trade", backref="trading_user", lazy=True)

class Trade(db.Model):
    """
    Single trade record (BUY/SELL).
    """
    id = db.Column(db.Integer, primary_key=True)
    symbol = db.Column(db.String(20), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    transaction_type = db.Column(db.String(10), nullable=False)  # BUY or SELL
    price = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    broker_order_id = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey("trading_user.id"), nullable=False)

with app.app_context():
    db.create_all()

##############################################################################
# 4. Decorators & Forms
##############################################################################
def admin_required(f):
    @functools.wraps(f)
    def wrap(*args, **kwargs):
        if not session.get("is_admin"):
            flash("Please log in as admin.", "danger")
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return wrap

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

##############################################################################
# 5. AngelOne Utility Functions
##############################################################################
def get_symbol_token(symbol):
    """
    Fetch the correct symbol token from AngelOne API.
    """
    obj = SmartConnect(api_key=API_KEY)
    session_data = obj.generateSession(CLIENT_CODE, CLIENT_PASSWORD, TOTP_SECRET)
    if not session_data or session_data.get("status") is False:
        print("Error: Invalid AngelOne credentials!")
        return None

    resp = obj.searchScrip("NSE", symbol)
    if resp.get("status") and resp.get("data"):
        return resp["data"][0]["symboltoken"]
    else:
        print(f"Error: Symbol '{symbol}' not found.")
        return None

def fetch_live_price(symbol):
    """
    Fetch live market price for any selected symbol from AngelOne.
    """
    obj = SmartConnect(api_key=API_KEY)
    session_data = obj.generateSession(CLIENT_CODE, CLIENT_PASSWORD, TOTP_SECRET)
    if not session_data or session_data.get("status") is False:
        print("Error: Invalid AngelOne credentials!")
        return None

    symbol_token = get_symbol_token(symbol)
    if not symbol_token:
        return None

    payload = {
        "exchange": "NSE",
        "tradingsymbol": symbol,
        "symboltoken": symbol_token
    }
    response = obj.ltpData(payload)
    if response.get("status"):
        return response["data"]["ltp"]
    else:
        print(f"Error fetching LTP for {symbol}")
        return None

def place_order(user, transaction_type, symbol, price, quantity):
    """
    Place an order for either AngelOne or Shonnay.
    """
    if user.broker == "angel":
        obj = SmartConnect(api_key=user.api_key)
        session_data = obj.generateSession(user.username, user.password, user.totp_token)
        if not session_data or session_data.get("status") is False:
            print(f"Error: Invalid API login for {user.username}")
            return None

        # Convert symbol to symbol_token
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
        resp = obj.placeOrder(orderparams)
        if resp.get("status"):
            return resp["data"]["orderid"]
        else:
            print(f"[AngelOne] Error placing order for {user.username}: {resp}")
            return None

    elif user.broker == "shonnay":
        # Simulate placing an order on "shonnay"
        return f"SH-{int(time.time())}"

    else:
        print(f"Unsupported broker: {user.broker}")
        return None

##############################################################################
# 6. Admin Login & Logout
##############################################################################
@app.route("/admin_login", methods=["GET", "POST"])
def admin_login():
    form = AdminLoginForm()
    if form.validate_on_submit():
        if (form.username.data == ADMIN_USERNAME 
            and bcrypt.check_password_hash(ADMIN_HASH, form.password.data)):
            session["is_admin"] = True
            flash("Welcome, Admin!", "success")
            return redirect(url_for("market_dashboard"))
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
# 7. Home & Market Dashboard
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
    Main Market Dashboard (displays real-time data, chart, buy/sell from chart).
    """
    return render_template("market_dashboard.html")

##############################################################################
# 8. API Endpoints for Market Data
##############################################################################
@app.route("/fetch_price")
@admin_required
def fetch_price():
    """
    GET /fetch_price?symbol=XYZ
    Returns live price for selected symbol.
    """
    symbol = request.args.get("symbol", "NIFTY 50")
    price = fetch_live_price(symbol)
    if price:
        return jsonify({"price": price})
    else:
        return jsonify({"error": f"Unable to fetch price for {symbol}"}), 400

@app.route("/market_trend")
@admin_required
def market_trend():
    """
    GET /market_trend?symbol=XYZ
    Simple trend detection: returns "UP" if price>1000, else "DOWN".
    """
    symbol = request.args.get("symbol", "NIFTY 50")
    price = fetch_live_price(symbol)
    trend = "UP" if price and price > 1000 else "DOWN"
    return jsonify({"trend": trend})

##############################################################################
# 9. Option Chain Routes
##############################################################################
def fetch_option_chain(symbol):
    """
    Return {"CALLS": [...], "PUTS": [...]} or None if error.
    """
    obj = SmartConnect(api_key=API_KEY)
    session_data = obj.generateSession(CLIENT_CODE, CLIENT_PASSWORD, TOTP_SECRET)
    if not session_data or session_data.get("status") is False:
        return None

    payload = {
        "exchange": "NFO",
        "tradingsymbol": symbol
    }
    resp = obj.getOptionChain(payload)
    if resp.get("status") and resp.get("data"):
        chain = {"CALLS": [], "PUTS": []}
        for item in resp["data"]:
            t = "CALLS" if item.get("instrumenttype") == "CE" else "PUTS"
            chain[t].append({
                "symbol": item["tradingsymbol"],
                "strike": item["strikeprice"],
                "ltp": item["ltp"],
                "expiry": item["expiry"]
            })
        return chain
    else:
        return None

@app.route("/option_chain", methods=["GET"])
@admin_required
def option_chain_page():
    """
    Renders the Option Chain page (HTML).
    """
    symbol = request.args.get("symbol", "NIFTY 50")
    return render_template("option_chain.html", symbol=symbol)

@app.route("/option_chain/<symbol>", methods=["GET"])
@admin_required
def option_chain_api(symbol):
    """
    Returns JSON of the option chain for the selected symbol.
    e.g. /option_chain/NIFTY 50
    """
    data = fetch_option_chain(symbol)
    if data:
        return jsonify(data)
    else:
        return jsonify({"error": "Unable to fetch option chain"}), 500

##############################################################################
# 10. Place Trade Route
##############################################################################
@app.route("/place_trade", methods=["POST"])
@admin_required
def place_trade():
    """
    POST /place_trade
    JSON body: {"symbol": "...", "type": "CALL"/"PUT", "user_ids": [...]} 
    or simplified if only the admin is placing the trade.
    """
    data = request.get_json()
    symbol = data.get("symbol")
    trade_type = data.get("type")  # "CALL" or "PUT"
    user_ids = data.get("user_ids", [])

    if not symbol or trade_type not in ["CALL", "PUT"]:
        return jsonify({"error": "Invalid trade parameters"}), 400

    # If no user_ids are provided, you might default to 1 user or handle error
    if not user_ids:
        # Example: assume single user_id=1 or handle differently
        return jsonify({"message": "No users selected!"}), 400

    # Fetch the option chain
    chain = fetch_option_chain(symbol)
    if not chain:
        return jsonify({"error": "Unable to fetch option chain"}), 500

    # Pick the first call or put
    if trade_type == "CALL" and chain["CALLS"]:
        selected_option = chain["CALLS"][0]
    elif trade_type == "PUT" and chain["PUTS"]:
        selected_option = chain["PUTS"][0]
    else:
        return jsonify({"error": "No valid options found"}), 400

    # Place orders for each selected user
    placed_orders = []
    failed_orders = []
    users = TradingUser.query.filter(TradingUser.id.in_(user_ids)).all()

    for user in users:
        qty = user.default_quantity
        order_id = place_order(
            user=user,
            transaction_type="BUY",
            symbol=selected_option["symbol"],
            price=selected_option["ltp"],
            quantity=qty
        )
        if order_id:
            # Save in DB
            t = Trade(
                symbol=selected_option["symbol"],
                quantity=qty,
                transaction_type="BUY",
                price=selected_option["ltp"],
                broker_order_id=order_id,
                user_id=user.id
            )
            db.session.add(t)
            placed_orders.append({"user": user.username, "order_id": order_id})

            # Broadcast via SocketIO
            socketio.emit("new_trade", {
                "symbol": t.symbol,
                "price": t.price,
                "broker_order_id": t.broker_order_id,
                "username": user.username,
                "broker": user.broker
            }, broadcast=True)
        else:
            failed_orders.append(user.username)

    db.session.commit()
    return jsonify({"success": True, "placed_orders": placed_orders, "failed_orders": failed_orders})

##############################################################################
# 11. Admin Dashboard & User Management
##############################################################################
@app.route("/admin_dashboard")
@admin_required
def admin_dashboard():
    page = request.args.get("page", 1, type=int)
    per_page = 10
    users_pag = TradingUser.query.paginate(page=page, per_page=per_page, error_out=False)
    trades_pag = Trade.query.paginate(page=page, per_page=per_page, error_out=False)

    return render_template(
        "admin_dashboard.html",
        users=users_pag.items,
        trades=trades_pag.items,
        total_users=users_pag.total,
        total_trades=trades_pag.total
    )

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

@app.route("/view_users")
@admin_required
def view_users():
    users = TradingUser.query.all()
    return render_template("view_users.html", users=users)

@app.route("/delete_user/<int:user_id>", methods=["POST"])
@admin_required
def delete_user(user_id):
    user = TradingUser.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        return jsonify({"success": True, "message": f"User '{user.username}' deleted"}), 200
    else:
        return jsonify({"success": False, "message": "User not found"}), 404

@app.route("/delete_all_users", methods=["POST"])
@admin_required
def delete_all_users():
    try:
        num_deleted = TradingUser.query.delete()
        db.session.commit()
        flash(f"Deleted {num_deleted} users", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error deleting users: {e}", "danger")
    return redirect(url_for("view_users"))

##############################################################################
# 12. Trades (View, WebSocket)
##############################################################################
@app.route("/trades")
@admin_required
def view_trades():
    trades = Trade.query.order_by(Trade.timestamp.desc()).all()
    return render_template("trades.html", trades=trades)

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
# 13. Additional Example for Live Chart
##############################################################################
@app.route("/live_chart")
@admin_required
def live_chart():
    """
    Display a live chart for a selected symbol using TradingView or custom logic.
    """
    symbol = request.args.get("symbol", "NIFTY 50")
    return render_template("live_chart.html", symbol=symbol)

##############################################################################
# 14. Main
##############################################################################
if __name__ == "__main__":
    socketio.run(app, debug=True)
