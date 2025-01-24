import os
import csv
import time
import random
import threading
from datetime import datetime
import functools

from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, session, jsonify
)
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_socketio import SocketIO, emit
from flask_wtf import FlaskForm
from wtforms import (
    StringField, PasswordField, SubmitField,
    IntegerField, FloatField, SelectField
)
from wtforms.validators import (
    DataRequired, Length, NumberRange, EqualTo
)
from flask_wtf.csrf import CSRFProtect


##############################################################################
# If you use .env, load it:
# from dotenv import load_dotenv
# load_dotenv()
##############################################################################

app = Flask(__name__, template_folder='.')
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY", "MY_SUPER_SECRET_KEY")
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL", "sqlite:///multi_broker.db")
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

    user_id = db.Column(db.Integer, db.ForeignKey('trading_user.id'), nullable=False)


with app.app_context():
    db.create_all()

##############################################################################
# Simulated "Live Price" from Angel
##############################################################################
def angel_fetch_live_price(symbol: str) -> float:
    """
    Return a random float around 1000 +/- 10 for demonstration.
    In real usage, you'd call the official AngelOne API.
    """
    return 1000 + random.uniform(-10, 10)

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
    broker = SelectField("Broker", choices=[("angel", "Angel"), ("shonnay", "Shonnay")])
    api_key = StringField("API Key", validators=[DataRequired(), Length(min=5, max=128)])
    totp_token = StringField("TOTP (optional)", validators=[Length(max=64)])
    default_quantity = IntegerField("Default Quantity", validators=[DataRequired(), NumberRange(min=1)])
    submit = SubmitField("Register User")

class PlaceOrderForm(FlaskForm):
    """
    For the Admin to place a manual trade on behalf of a user.
    """
    user_id = SelectField("User", coerce=int)  # we'll fill choices at runtime
    symbol = StringField("Symbol", validators=[DataRequired(), Length(min=1, max=20)])
    quantity = IntegerField("Quantity (0 => use default)", default=0)
    transaction_type = SelectField("Type", choices=[("BUY", "Buy"), ("SELL", "Sell")])
    price = FloatField("Price", validators=[DataRequired(), NumberRange(min=0)])
    submit = SubmitField("Place Order")

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
    Single admin login. No separate login for each trading user.
    """
    form = AdminLoginForm()
    if form.validate_on_submit():
        # Check credentials
        if form.username.data == ADMIN_USERNAME and bcrypt.check_password_hash(ADMIN_HASH, form.password.data):
            session["is_admin"] = True
            flash("Welcome, Admin!", "success")
            return redirect(url_for("admin_dashboard"))
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
    if session.get("is_admin"):
        return redirect(url_for("admin_dashboard"))
    else:
        return redirect(url_for("admin_login"))

##############################################################################
# Admin Dashboard
##############################################################################
@app.route("/admin_dashboard")
@admin_required
def admin_dashboard():
    total_users = TradingUser.query.count()
    total_trades = Trade.query.count()
    return render_template("admin_dashboard.html",
                           total_users=total_users,
                           total_trades=total_trades)

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

        new_user = TradingUser(
            username=form.username.data,
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

##############################################################################
# Place Orders Page (MANUAL + AUTO + STOP-LOSS)
##############################################################################
@app.route("/place_order", methods=["GET", "POST"])
@admin_required
def place_order():
    """
    A single page with:
     - Manual Order Form
     - Auto Trading (Buy) config
     - Stop-Loss config
     - Explanation tab
    """
    # 1) Manual trade form
    form = PlaceOrderForm()
    trading_users = TradingUser.query.order_by(TradingUser.username.asc()).all()
    form.user_id.choices = [(u.id, f"{u.username} ({u.broker})") for u in trading_users]

    if form.validate_on_submit():
        user = TradingUser.query.get(form.user_id.data)
        if not user:
            flash("User not found.", "danger")
            return redirect(url_for("place_order"))

        # If quantity=0 => fallback to user.default_quantity
        qty = form.quantity.data
        if qty <= 0:
            qty = user.default_quantity

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
        db.session.commit()

        # Emit socket event
        socketio.emit('new_trade', {
            "symbol": new_trade.symbol,
            "price": new_trade.price,
            "broker_order_id": new_trade.broker_order_id,
            "username": user.username,
            "broker": user.broker
        }, broadcast=True)

        flash("Manual trade placed!", "success")
        return redirect(url_for("view_trades"))

    return render_template("place_order.html", form=form, users=trading_users)

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

@app.route("/api/auto_trade", methods=["POST"])
@admin_required
def api_auto_trade():
    """
    JSON body example:
    {
      "user_id": 2,
      "symbol": "INFY",
      "quantity": 0,  # => fallback
      "condition": "Condition 1" or "Condition 2",
      "basis": "fixed"/"points"/"percentage",
      "threshold_value": 1500,
      "reference_price": 1450
    }
    """
    data = request.get_json()
    user_id = data.get("user_id")
    user = TradingUser.query.get(user_id)
    if not user:
        return jsonify({"success": False, "message": "Invalid user_id"}), 400

    symbol = data.get("symbol")
    quantity = int(data.get("quantity", 0))
    condition = data.get("condition")
    basis = data.get("basis")
    threshold_value = float(data.get("threshold_value", 0))
    reference_price = float(data.get("reference_price", 0))

    if quantity <= 0:
        quantity = user.default_quantity

    if not symbol or not condition or not basis:
        return jsonify({"success": False, "message": "Missing fields."}), 400

    auto_trade_flags[user_id] = False

    def monitor_auto_trade(u_id, sym, qty, cond, bas, thresh_val, ref_price):
        while not auto_trade_flags[u_id]:
            live_price = angel_fetch_live_price(sym)
            if live_price is None:
                time.sleep(5)
                continue

            triggered = False
            if cond == "Condition 1":  # >=
                if bas == "fixed" and live_price >= thresh_val:
                    triggered = True
                elif bas == "points" and live_price >= (ref_price + thresh_val):
                    triggered = True
                elif bas == "percentage" and live_price >= (ref_price * (1 + thresh_val/100)):
                    triggered = True
            else:  # Condition 2 => >
                if bas == "fixed" and live_price > thresh_val:
                    triggered = True
                elif bas == "points" and live_price > (ref_price + thresh_val):
                    triggered = True
                elif bas == "percentage" and live_price > (ref_price * (1 + thresh_val/100)):
                    triggered = True

            if triggered:
                bo_id = f"{user.broker.upper()}-{int(time.time())}"
                new_trade = Trade(
                    symbol=sym,
                    quantity=qty,
                    transaction_type="BUY",
                    price=live_price,
                    broker_order_id=bo_id,
                    user_id=u_id
                )
                db.session.add(new_trade)
                db.session.commit()
                socketio.emit('new_trade', {
                    "symbol": new_trade.symbol,
                    "price": new_trade.price,
                    "broker_order_id": new_trade.broker_order_id,
                    "username": user.username,
                    "broker": user.broker
                }, broadcast=True)
                break

            time.sleep(5)

    threading.Thread(
        target=monitor_auto_trade,
        args=(user_id, symbol, quantity, condition, basis, threshold_value, reference_price),
        daemon=True
    ).start()

    return jsonify({"success": True, "message": "Auto trade started."}), 200

@app.route("/api/stop_auto_trade", methods=["POST"])
@admin_required
def api_stop_auto_trade():
    data = request.get_json()
    user_id = data.get("user_id")
    if not user_id:
        return jsonify({"success": False, "message": "Missing user_id"}), 400

    auto_trade_flags[user_id] = True
    return jsonify({"success": True, "message": "Auto trade stopped."}), 200

@app.route("/api/auto_stoploss_sell", methods=["POST"])
@admin_required
def api_auto_stoploss_sell():
    """
    JSON example:
    {
      "user_id": 2,
      "symbol": "INFY",
      "buy_price": 1000,
      "quantity": 0,   # => fallback
      "scenario": "1" or "2",
      "stop_loss_type": "percentage"/"points"/"fixed",
      "fixed_stop_loss": "5" (only if type==fixed)
    }
    """
    data = request.get_json()
    user_id = data.get("user_id")
    user = TradingUser.query.get(user_id)
    if not user:
        return jsonify({"success": False, "message": "Invalid user_id"}), 400

    symbol = data.get("symbol")
    buy_price = float(data.get("buy_price", 0))
    quantity = int(data.get("quantity", 0))
    scenario = data.get("scenario")
    sl_type = data.get("stop_loss_type")
    fixed_stop_loss = data.get("fixed_stop_loss")

    if quantity <= 0:
        quantity = user.default_quantity

    if not symbol or buy_price <= 0 or not scenario or not sl_type:
        return jsonify({"success": False, "message": "Missing fields"}), 400

    stop_loss_flags[user_id] = False

    def monitor_stop_loss(u_id, sym, bp, qty, scn, s_type, fsl):
        highest_price = bp
        # init stop_loss
        if s_type == "percentage":
            stop_loss = bp * 0.95
        elif s_type == "points":
            stop_loss = bp - 5
        elif s_type == "fixed" and fsl is not None:
            stop_loss = float(fsl)
        else:
            return

        while not stop_loss_flags[u_id]:
            live_price = angel_fetch_live_price(sym)
            if live_price is None:
                time.sleep(5)
                continue

            if scn == "1":  # fixed
                if live_price <= stop_loss:
                    bo_id = f"{user.broker.upper()}-{int(time.time())}"
                    new_trade = Trade(
                        symbol=sym,
                        quantity=qty,
                        transaction_type="SELL",
                        price=live_price,
                        broker_order_id=bo_id,
                        user_id=u_id
                    )
                    db.session.add(new_trade)
                    db.session.commit()
                    socketio.emit('new_trade', {
                        "symbol": new_trade.symbol,
                        "price": new_trade.price,
                        "broker_order_id": new_trade.broker_order_id,
                        "username": user.username,
                        "broker": user.broker
                    }, broadcast=True)
                    break
            else:  # trailing
                if live_price > highest_price:
                    highest_price = live_price
                    if s_type == "percentage":
                        stop_loss = highest_price * 0.95
                    elif s_type == "points":
                        stop_loss = highest_price - 5
                    # if fixed => do not move

                if live_price <= stop_loss:
                    bo_id = f"{user.broker.upper()}-{int(time.time())}"
                    new_trade = Trade(
                        symbol=sym,
                        quantity=qty,
                        transaction_type="SELL",
                        price=live_price,
                        broker_order_id=bo_id,
                        user_id=u_id
                    )
                    db.session.add(new_trade)
                    db.session.commit()
                    socketio.emit('new_trade', {
                        "symbol": new_trade.symbol,
                        "price": new_trade.price,
                        "broker_order_id": new_trade.broker_order_id,
                        "username": user.username,
                        "broker": user.broker
                    }, broadcast=True)
                    break

            time.sleep(5)

    threading.Thread(
        target=monitor_stop_loss,
        args=(user_id, symbol, buy_price, quantity, scenario, sl_type, fixed_stop_loss),
        daemon=True
    ).start()

    return jsonify({"success": True, "message": "Stop-loss monitoring started."}), 200

@app.route("/api/stop_auto_stoploss_sell", methods=["POST"])
@admin_required
def api_stop_auto_stoploss_sell():
    data = request.get_json()
    user_id = data.get("user_id")
    if not user_id:
        return jsonify({"success": False, "message": "Missing user_id"}), 400

    stop_loss_flags[user_id] = True
    return jsonify({"success": True, "message": "Stop-loss monitoring stopped."}), 200

##############################################################################
# MAIN
##############################################################################
if __name__ == "__main__":
    socketio.run(app, debug=True)
