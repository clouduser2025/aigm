import os
import csv
import time
import random
import threading
from datetime import datetime
import functools
from SmartApi import SmartConnect  # ✅ Ensure the AngelOne Smart API is installed

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




##############################################################################
# If you use .env, load it:
# from dotenv import load_dotenv
# load_dotenv()
##############################################################################

app = Flask(__name__, template_folder='.')
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY", "MY_SUPER_SECRET_KEY")
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL", "sqlite:///multi_broker_trade.db")
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

@app.route("/view_users", methods=["GET"])
@admin_required
def view_users():
    """
    View all registered users sorted by creation date.
    """
    sort_order = request.args.get("order", "desc")  # Default: descending order
    if sort_order == "asc":
        users = TradingUser.query.order_by(TradingUser.created_at.asc()).all()
    else:
        users = TradingUser.query.order_by(TradingUser.created_at.desc()).all()

    return render_template("view_users.html", users=users)

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
        flash(f"User '{user.username}' deleted successfully.", "success")
    else:
        flash("User not found!", "danger")

    return redirect(url_for("view_users"))


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

##############################################################################
# Place Orders Page (MANUAL + AUTO + STOP-LOSS)
##############################################################################
@app.route("/place_order", methods=["GET", "POST"])
@admin_required
def place_order():
    form = PlaceOrderForm()

    # ✅ Ensure user list is loaded before validation
    trading_users = TradingUser.query.order_by(TradingUser.username.asc()).all()
    form.user_ids.choices = [(u.id, f"{u.username} ({u.broker})") for u in trading_users]

    if form.validate_on_submit():  # ✅ Validate only after choices are set
        selected_users = TradingUser.query.filter(TradingUser.id.in_(form.user_ids.data)).all()
        if not selected_users:
            flash("No valid users selected!", "danger")
            return redirect(url_for("place_order"))

        for user in selected_users:
            qty = form.quantity.data if form.quantity.data > 0 else user.default_quantity
            broker_order_id = f"{user.broker.upper()}-{int(time.time())}"  # ✅ Fix placement

            new_trade = Trade(
                symbol=form.symbol.data,
                quantity=qty,
                transaction_type=form.transaction_type.data,
                price=form.price.data,
                broker_order_id=broker_order_id,
                user_id=user.id
            )

            db.session.add(new_trade)

            # ✅ Only emit after commit
            socketio.emit('new_trade', {
                "symbol": new_trade.symbol,
                "price": new_trade.price,
                "broker_order_id": new_trade.broker_order_id,
                "username": user.username,
                "broker": user.broker
            }, broadcast=True)

        db.session.commit()  # ✅ Commit only once at the end

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

    # Handle Angel Broker
    if broker == "angel":
        try:
            obj = SmartConnect(api_key=api_key)
            session_data = obj.generateSession(user.username, totp_token)
            feed_token = obj.getfeedToken()

            # Prepare and place the order
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
            return jsonify({"success": True, "message": f"Order placed successfully. Order ID: {order_id}"}), 200

        except Exception as e:
            return jsonify({"success": False, "message": f"Error placing order: {e}"}), 500

    # Placeholder for Shonnay Broker
    elif broker == "shonnay":
        try:
            # TODO: Integrate Shonnay API here
            return jsonify({"success": True, "message": "Shonnay integration will be added soon."}), 200

        except Exception as e:
            return jsonify({"success": False, "message": f"Error placing Shonnay order: {e}"}), 500

    else:
        return jsonify({"success": False, "message": f"Broker {broker} not supported yet."}), 400
    
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


@app.route("/api/auto_trade", methods=["POST"])
@admin_required
def api_auto_trade():
    """
    Starts auto trading for a user with required stop-loss configuration.
    JSON body example:
    {
      "user_id": 2,
      "symbol": "INFY",
      "condition": "Condition 1" or "Condition 2",
      "basis": "fixed"/"points"/"percentage",
      "threshold_value": 1500,
      "reference_price": 1450,
      "stop_loss_type": "percentage"/"points"/"fixed",
      "stop_loss_value": 5
    }
    """
    data = request.get_json()
    user_ids = data.get("user_ids", [])
    selected_users = TradingUser.query.filter(TradingUser.id.in_(user_ids)).all()
    if not selected_users:
        return jsonify({"success": False, "message": "No valid users selected."}), 400


    if not selected_users:
        return jsonify({"success": False, "message": "No valid users selected."}), 400

    for user in selected_users:  # ✅ Ensure `user` is defined inside loop
        quantity = user.default_quantity
        broker = user.broker
        api_key = user.api_key
        totp_token = user.totp_token


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

    # Handle Angel Broker
    if broker == "angel":
        obj = SmartConnect(api_key=api_key)
        session_data = obj.generateSession(user.username, totp_token)
        feed_token = obj.getfeedToken()

        def monitor_auto_trade(user):  # ✅ Add user parameter

            while True:
                live_price = angel_fetch_live_price(symbol)
                if live_price is None:
                    time.sleep(5)
                    continue

                triggered = False
                # Check trade condition
                if condition == "Condition 1" and basis == "fixed" and live_price >= threshold_value:
                    triggered = True
                elif condition == "Condition 2" and basis == "fixed" and live_price > threshold_value:
                    triggered = True

                if triggered:
                    try:
                        # Place the trade
                        orderparams = {
                            "variety": "NORMAL",
                            "tradingsymbol": symbol,
                            "symboltoken": "1234",  # Replace dynamically
                            "transactiontype": "BUY",
                            "exchange": "NSE",
                            "ordertype": "LIMIT",
                            "producttype": "INTRADAY",
                            "duration": "DAY",
                            "price": live_price,
                            "quantity": quantity
                        }
                        order_id = obj.placeOrder(orderparams)

                        # Monitor Stop-Loss
                        monitor_stop_loss(user, symbol, live_price, stop_loss_type, stop_loss_value, quantity)

                        break
                    except Exception as e:
                        print(f"Error placing order: {e}")
                        break

                time.sleep(5)

        def monitor_stop_loss(user, symbol, entry_price, sl_type, sl_value, qty):

            while True:
                live_price = angel_fetch_live_price(symbol)
                if live_price is None:
                    time.sleep(5)
                    continue

                # Determine stop-loss level
                if sl_type == "percentage":
                    stop_loss = entry_price * (1 - sl_value / 100)
                elif sl_type == "points":
                    stop_loss = entry_price - sl_value
                elif sl_type == "fixed":
                    stop_loss = sl_value

                if live_price <= stop_loss:
                    try:
                        # Place a sell order
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
                        obj.placeOrder(orderparams)
                        break
                    except Exception as e:
                        print(f"Error placing stop-loss order: {e}")
                        break

            for user in selected_users:
                if auto_trade_flags.get(user.id, False):
                    continue  # Skip if auto-trade is already running
                auto_trade_flags[user.id] = True
                threading.Thread(target=monitor_auto_trade, args=(user,), daemon=True).start()


        return jsonify({"success": True, "message": "Auto trade started with stop-loss."}), 200

    # Placeholder for Shonnay Broker
    elif broker == "shonnay":
        try:
            # TODO: Integrate Shonnay API here
            return jsonify({"success": True, "message": "Shonnay integration will be added soon."}), 200
        except Exception as e:
            return jsonify({"success": False, "message": f"Error in Shonnay auto-trade: {e}"}), 500

    else:
        return jsonify({"success": False, "message": f"Broker {broker} not supported yet."}), 400


##############################################################################
# MAIN
##############################################################################
if __name__ == "__main__":
    socketio.run(app, debug=True)
