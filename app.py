import os
import csv
import time
import random
import threading
from datetime import datetime
import functools

# Angel API module (SmartConnect)
from SmartApi import SmartConnect  # Ensure the AngelOne Smart API is installed

# Dummy Shonnay API integration (simulate similar functionality)
class ShonayConnect:
    def __init__(self, api_key):
        self.api_key = api_key

    def login(self, userid, password, twoFA, vendor_code, api_secret, imei):
        # Simulate a successful login (dummy values)
        return {"session": "dummy_session"}

    def place_order(self, buy_or_sell, product_type, exchange, tradingsymbol,
                    quantity, discloseqty, price_type, price=0.0, trigger_price=None,
                    retention='DAY', amo='NO', remarks=None):
        # Simulate placing an order and return a dummy order ID
        return f"SH-{int(time.time())}"

# Import your database object from data.py
from data import db
from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, session, jsonify, send_from_directory
)
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_socketio import SocketIO, emit
from flask_wtf import FlaskForm
from wtforms.validators import DataRequired, Length, NumberRange
from wtforms import (
    StringField, PasswordField, SubmitField,
    IntegerField, FloatField, SelectField, SelectMultipleField
)
from flask_wtf.csrf import CSRFProtect

##############################################################################
# App configuration
##############################################################################
app = Flask(__name__, template_folder='.')
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY", "MY_SUPER_SECRET_KEY")
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL", "sqlite:///multi_broker_traders_fed1.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)
socketio = SocketIO(app, cors_allowed_origins="*")

##############################################################################
# Admin Credentials
##############################################################################
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin")
ADMIN_HASH = bcrypt.generate_password_hash(ADMIN_PASSWORD).decode("utf-8")

##############################################################################
# Database Models
##############################################################################
class TradingUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    broker = db.Column(db.String(20), nullable=False)  # "angel" or "shonnay"
    api_key = db.Column(db.String(128), nullable=False)
    totp_token = db.Column(db.String(64), nullable=True)
    default_quantity = db.Column(db.Integer, default=1)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    trades = db.relationship("Trade", backref="trading_user", lazy=True)

class Trade(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    symbol = db.Column(db.String(20), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    transaction_type = db.Column(db.String(10), nullable=False)  # "BUY" or "SELL"
    price = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    broker_order_id = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('trading_user.id'), nullable=False)

with app.app_context():
    db.create_all()

##############################################################################
# Simulated Live Price Functions
##############################################################################
def angel_fetch_live_price(symbol: str) -> float:
    return 1000 + random.uniform(-10, 10)

def shonnay_fetch_live_price(symbol: str) -> float:
    return 1000 + random.uniform(-8, 8)

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
# Global flag to prevent duplicate auto-trade threads
##############################################################################
auto_trade_flags = {}

##############################################################################
# Forms
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
    user_ids = SelectMultipleField("Users", coerce=int)
    symbol = StringField("Symbol", validators=[DataRequired(), Length(min=1, max=20)])
    quantity = IntegerField("Quantity (0 => use default)", default=0)
    transaction_type = SelectField("Type", choices=[("BUY", "Buy"), ("SELL", "Sell")])
    price = FloatField("Price", validators=[DataRequired(), NumberRange(min=0)])
    submit = SubmitField("Place Order")

##############################################################################
# Routes
##############################################################################
@app.route("/admin_login", methods=["GET", "POST"])
def admin_login():
    form = AdminLoginForm()
    if form.validate_on_submit():
        if form.username.data == ADMIN_USERNAME and bcrypt.check_password_hash(ADMIN_HASH, form.password.data):
            session["is_admin"] = True
            flash("Welcome, Admin!", "success")
            return redirect(url_for("admin_dashboard"))
        else:
            flash("Invalid admin credentials!", "danger")
            return redirect(url_for("admin_login"))
    return render_template("admin_login.html", form=form)

@app.route("/admin_dashboard")
@admin_required
def admin_dashboard():
    users = TradingUser.query.all()
    trades = Trade.query.order_by(Trade.timestamp.desc()).all()
    return render_template("admin_dashboard.html", users=users, trades=trades)

@app.route("/place_order", methods=["GET", "POST"])
@admin_required
def place_order():
    form = PlaceOrderForm()
    trading_users = TradingUser.query.order_by(TradingUser.username.asc()).all()
    form.user_ids.choices = [(u.id, f"{u.username} ({u.broker})") for u in trading_users]
    if form.validate_on_submit():
        selected_users = TradingUser.query.filter(TradingUser.id.in_(form.user_ids.data)).all()
        if not selected_users:
            flash("No valid users selected!", "danger")
            return redirect(url_for("place_order"))
        for user in selected_users:
            qty = form.quantity.data if form.quantity.data > 0 else user.default_quantity
            broker_order_id = f"{user.broker.upper()}-{int(time.time())}"
            new_trade = Trade(
                symbol=form.symbol.data,
                quantity=qty,
                transaction_type=form.transaction_type.data,
                price=form.price.data,
                broker_order_id=broker_order_id,
                user_id=user.id
            )
            db.session.add(new_trade)
            socketio.emit('new_trade', {
                "symbol": new_trade.symbol,
                "price": new_trade.price,
                "broker_order_id": new_trade.broker_order_id,
                "username": user.username,
                "broker": user.broker
            }, broadcast=True)
        db.session.commit()
        flash("Manual trade placed!", "success")
        return redirect(url_for("admin_dashboard"))
    return render_template("place_order.html", form=form, users=trading_users)

# ---------------------------
# API Endpoint: Manual Trade
# (For a single user; adjust frontend if you want multiple.)
# ---------------------------
@app.route("/api/manual_trade", methods=["POST"])
@admin_required
def api_manual_trade():
    data = request.get_json()
    user_id = data.get("user_id")  # Expect a single user id
    user = TradingUser.query.get(user_id)
    if not user:
        return jsonify({"success": False, "message": "Invalid user_id"}), 400
    quantity = user.default_quantity
    broker = user.broker
    api_key = user.api_key
    totp_token = user.totp_token
    symbol = data.get("symbol")
    transaction_type = data.get("transaction_type")
    price = float(data.get("price", 0))
    exchange = data.get("exchange", "NSE")
    if not symbol or not transaction_type or price <= 0:
        return jsonify({"success": False, "message": "Missing or invalid trade details."}), 400

    if broker == "angel":
        try:
            obj = SmartConnect(api_key=api_key)
            session_data = obj.generateSession(user.username, totp_token)
            feed_token = obj.getfeedToken()
            orderparams = {
                "variety": "NORMAL",
                "tradingsymbol": symbol,
                "symboltoken": "1234",  # Replace dynamically
                "transactiontype": transaction_type,
                "exchange": exchange,
                "ordertype": "LIMIT",
                "producttype": "INTRADAY",
                "duration": "DAY",
                "price": price,
                "quantity": quantity
            }
            order_id = obj.placeOrder(orderparams)
            return jsonify({"success": True, "message": f"Angel order placed. Order ID: {order_id}"}), 200
        except Exception as e:
            return jsonify({"success": False, "message": f"Error placing Angel order: {e}"}), 500
    elif broker == "shonnay":
        try:
            sh_api = ShonayConnect(api_key=api_key)
            ret = sh_api.login(userid=user.username, password="dummy_pwd", twoFA="dummy_2fa",
                               vendor_code="VC123", api_secret=api_key, imei="dummy_imei")
            order_id = sh_api.place_order(buy_or_sell='B' if transaction_type=="BUY" else 'S',
                                          product_type='C',
                                          exchange=exchange,
                                          tradingsymbol=symbol,
                                          quantity=quantity,
                                          discloseqty=0,
                                          price_type='SL-LMT',
                                          price=price,
                                          trigger_price=price-0.5,  # dummy trigger price
                                          retention='DAY',
                                          amo='NO',
                                          remarks='sh_manual_order')
            socketio.emit('new_trade', {
                "symbol": symbol,
                "price": price,
                "broker_order_id": order_id,
                "username": user.username,
                "broker": user.broker
            }, broadcast=True)
            return jsonify({"success": True, "message": f"Shonnay order placed. Order ID: {order_id}"}), 200
        except Exception as e:
            return jsonify({"success": False, "message": f"Error placing Shonnay order: {e}"}), 500
    else:
        return jsonify({"success": False, "message": f"Broker {broker} not supported."}), 400

# ---------------------------
# API Endpoint: Auto Trade with Stop-Loss
# ---------------------------
@app.route("/api/auto_trade", methods=["POST"])
@admin_required
def api_auto_trade():
    data = request.get_json()
    user_ids = data.get("user_ids", [])
    selected_users = TradingUser.query.filter(TradingUser.id.in_(user_ids)).all()
    if not selected_users:
        return jsonify({"success": False, "message": "No valid users selected."}), 400

    symbol = data.get("symbol")
    condition = data.get("condition")
    basis = data.get("basis")
    threshold_value = float(data.get("threshold_value", 0))
    reference_price = float(data.get("reference_price", 0))
    stop_loss_type = data.get("stop_loss_type")
    stop_loss_value = data.get("stop_loss_value")
    points_condition = float(data.get("points_condition", 0))
    if not symbol or not condition or not basis or not stop_loss_type or stop_loss_value is None:
        return jsonify({"success": False, "message": "Missing required fields."}), 400

    # For simplicity, assume all selected users use the same broker.
    user = selected_users[0]
    broker = user.broker
    api_key = user.api_key
    totp_token = user.totp_token

    if broker == "angel":
        obj = SmartConnect(api_key=api_key)
        session_data = obj.generateSession(user.username, totp_token)
        feed_token = obj.getfeedToken()

        def monitor_auto_trade(user):
            while True:
                live_price = angel_fetch_live_price(symbol)
                if live_price is None:
                    time.sleep(5)
                    continue
                triggered = False
                # For demonstration, use fixed basis conditions
                if condition == "Condition 1" and basis == "fixed" and live_price >= threshold_value:
                    triggered = True
                elif condition == "Condition 2" and basis == "fixed" and live_price > threshold_value:
                    triggered = True
                if triggered:
                    try:
                        orderparams = {
                            "variety": "NORMAL",
                            "tradingsymbol": symbol,
                            "symboltoken": "1234",
                            "transactiontype": "BUY",
                            "exchange": "NSE",
                            "ordertype": "LIMIT",
                            "producttype": "INTRADAY",
                            "duration": "DAY",
                            "price": live_price,
                            "quantity": user.default_quantity
                        }
                        order_id = obj.placeOrder(orderparams)
                        # Start trailing stop-loss monitoring:
                        monitor_stop_loss(user, symbol, live_price, stop_loss_type, stop_loss_value, user.default_quantity, points_condition, obj)
                        break
                    except Exception as e:
                        print(f"Error placing BUY order for {user.username}: {e}")
                        break
                time.sleep(5)

        def monitor_stop_loss(user, symbol, entry_price, sl_type, sl_value, qty, pts_cond, smart_obj):
            base = entry_price
            highest = entry_price
            while True:
                live_price = angel_fetch_live_price(symbol)
                if live_price is None:
                    time.sleep(5)
                    continue
                if live_price > highest:
                    highest = live_price
                if pts_cond < 0 and live_price < base:
                    base = live_price
                if sl_type == "percentage":
                    current_sl = base + (highest - base) * (float(sl_value) / 100.0)
                elif sl_type == "points":
                    current_sl = highest - float(sl_value)
                elif sl_type == "fixed":
                    current_sl = float(sl_value)
                else:
                    current_sl = base
                print(f"[Angel SL] {user.username}: Live={live_price:.2f}, Base={base:.2f}, Highest={highest:.2f}, SL={current_sl:.2f}")
                if live_price <= current_sl:
                    try:
                        orderparams = {
                            "variety": "NORMAL",
                            "tradingsymbol": symbol,
                            "symboltoken": "1234",
                            "transactiontype": "SELL",
                            "exchange": "NSE",
                            "ordertype": "LIMIT",
                            "producttype": "INTRADAY",
                            "duration": "DAY",
                            "price": live_price,
                            "quantity": qty
                        }
                        smart_obj.placeOrder(orderparams)
                        break
                    except Exception as e:
                        print(f"Error placing SELL order for {user.username}: {e}")
                        break
                time.sleep(5)

        for user in selected_users:
            if auto_trade_flags.get(user.id, False):
                continue
            auto_trade_flags[user.id] = True
            threading.Thread(target=monitor_auto_trade, args=(user,), daemon=True).start()
        return jsonify({"success": True, "message": "Angel auto trade started with stop-loss."}), 200

    elif broker == "shonnay":
        try:
            def monitor_auto_trade_shonnay(user):
                while True:
                    live_price = shonnay_fetch_live_price(symbol)
                    if live_price is None:
                        time.sleep(5)
                        continue
                    triggered = False
                    if condition == "Condition 1" and basis == "fixed" and live_price >= threshold_value:
                        triggered = True
                    elif condition == "Condition 2" and basis == "fixed" and live_price > threshold_value:
                        triggered = True
                    if triggered:
                        try:
                            sh_api = ShonayConnect(api_key=api_key)
                            ret = sh_api.login(userid=user.username, password="dummy_pwd", twoFA="dummy_2fa",
                                               vendor_code="VC123", api_secret=api_key, imei="dummy_imei")
                            order_id = sh_api.place_order(
                                buy_or_sell='B',
                                product_type='C',
                                exchange="NSE",
                                tradingsymbol=symbol,
                                quantity=user.default_quantity,
                                discloseqty=0,
                                price_type='SL-LMT',
                                price=live_price,
                                trigger_price=live_price - 0.5,
                                retention='DAY',
                                amo='NO',
                                remarks='sh_auto_order'
                            )
                            print(f"Shonnay auto trade for {user.username} at {live_price}, Order ID: {order_id}")
                            break
                        except Exception as e:
                            print(f"Error placing Shonnay auto trade for {user.username}: {e}")
                            break
                    time.sleep(5)
            for user in selected_users:
                if auto_trade_flags.get(user.id, False):
                    continue
                auto_trade_flags[user.id] = True
                threading.Thread(target=monitor_auto_trade_shonnay, args=(user,), daemon=True).start()
            return jsonify({"success": True, "message": "Shonnay auto trade started (simulated)."}), 200
        except Exception as e:
            return jsonify({"success": False, "message": f"Error in Shonnay auto trade: {e}"}), 500
    else:
        return jsonify({"success": False, "message": f"Broker {broker} not supported."}), 400

# ---------------------------
# Live Chart Endpoint (TradingView widget page)
# ---------------------------
@app.route("/live_chart", methods=["GET"])
@admin_required
def live_chart():
    tradingsymbol = request.args.get("tradingsymbol", "INFY")
    exchange = request.args.get("exchange", "NSE")
    return render_template("live_chart.html", tradingsymbol=tradingsymbol, exchange=exchange)

# ---------------------------
# Socket.IO: Send initial trades (optional)
# ---------------------------
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

# ---------------------------
# MAIN
# ---------------------------
if __name__ == "__main__":
    socketio.run(app, debug=True)
