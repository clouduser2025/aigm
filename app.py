# app.py

from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    logout_user,
    login_required,
    current_user,
)
import pyotp
import time
from threading import Thread
from logzero import logger
from datetime import datetime, timedelta
from twilio.rest import Client
import os
import uuid
from SmartApi.smartConnect import SmartConnect

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'  # Replace with a secure secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///trading_dashboard.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'index'

# Twilio Configuration
TWILIO_ACCOUNT_SID = 'your_twilio_account_sid'      # Replace with your Twilio Account SID
TWILIO_AUTH_TOKEN = 'your_twilio_auth_token'        # Replace with your Twilio Auth Token
TWILIO_PHONE_NUMBER = '+1234567890'                 # Replace with your Twilio phone number

twilio_client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

# ---------------------------------
# Database Models
# ---------------------------------

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(150), unique=True, nullable=False)
    broker = db.Column(db.String(50), nullable=False)  # 'angel' or 'shonnay'
    api_key = db.Column(db.String(150), nullable=False)  # For SmartConnect
    username = db.Column(db.String(150), nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)
    totp_secret = db.Column(db.String(150), nullable=False)
    default_quantity = db.Column(db.Integer, nullable=False, default=1)
    auth_token = db.Column(db.String(500), nullable=True)        # SmartConnect auth token
    refresh_token = db.Column(db.String(500), nullable=True)     # SmartConnect refresh token

    trades = db.relationship('Trade', backref='owner', lazy=True)

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

class Trade(db.Model):
    __tablename__ = 'trades'
    id = db.Column(db.Integer, primary_key=True)
    trade_id = db.Column(db.String(50), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    symbol = db.Column(db.String(50), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    transaction_type = db.Column(db.String(10), nullable=False)  # 'BUY' or 'SELL'
    price = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

class RegistrationToken(db.Model):
    __tablename__ = 'registration_tokens'
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(100), unique=True, nullable=False)
    mobile_number = db.Column(db.String(20), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)

# Create all tables
with app.app_context():
    db.create_all()

# ---------------------------------
# User Loader for Flask-Login
# ---------------------------------

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ---------------------------------
# Helper Functions
# ---------------------------------

def send_registration_sms(mobile_number, token):
    """
    Sends an SMS with the registration link to the user's mobile number.
    """
    try:
        registration_link = url_for('register_via_token', token=token, _external=True)
        message_body = f"Welcome to Multi-Broker Trading Dashboard! Complete your registration here: {registration_link}"
        message = twilio_client.messages.create(
            body=message_body,
            from_=TWILIO_PHONE_NUMBER,
            to=mobile_number
        )
        logger.info(f"Sent registration SMS to {mobile_number}: SID {message.sid}")
    except Exception as e:
        logger.error(f"Failed to send SMS to {mobile_number}: {e}")

def generate_registration_token():
    """
    Generates a unique registration token.
    """
    return str(uuid.uuid4())

def place_order(order_details):
    """
    Places an order via SmartConnect.
    """
    user = User.query.get(order_details['user_id'])
    if not user.auth_token:
        logger.error(f"User {user.user_id} is not authenticated with SmartConnect.")
        return

    try:
        smart_api = SmartConnect(api_key=user.api_key)
        smart_api.setSession(user.auth_token)

        # Example of placing an order (this will vary based on actual API and order details)
        order_params = {
            "variety": "NORMAL",
            "tradingsymbol": order_details['symbol'],
            "symboltoken": "symbol_token_here",  # Replace with actual symbol token
            "transactiontype": order_details['transactiontype'],
            "exchange": "NSE",
            "ordertype": "LIMIT",
            "producttype": "MIS",
            "duration": "DAY",
            "price": order_details['price'],
            "quantity": order_details['quantity']
        }

        response = smart_api.placeOrder(order_params)
        logger.info(f"Order placed: {response}")
        
        # Record the trade in the database
        trade = Trade(
            trade_id=response.get('data', {}).get('orderid', f"T{int(time.time())}"),
            user_id=user.id,
            symbol=order_details['symbol'],
            quantity=order_details['quantity'],
            transaction_type=order_details['transactiontype'],
            price=order_details['price'],
            timestamp=datetime.utcnow()
        )
        db.session.add(trade)
        db.session.commit()
        logger.info(f"Trade recorded: {trade.trade_id}")

    except Exception as e:
        logger.error(f"Error placing order for user {user.user_id}: {e}")

def fetch_live_price(user, symbol):
    """
    Fetches live price for a symbol from Angel One Smart API.
    """
    if not user.auth_token:
        logger.warning(f"User {user.user_id} has no auth token; cannot fetch live price.")
        return None

    try:
        smart_api = SmartConnect(api_key=user.api_key)
        smart_api.setSession(user.auth_token)

        ltp_data = smart_api.ltpData("NSE", symbol)
        live_price = float(ltp_data['data'][symbol]['lastPrice'])
        logger.info(f"Fetched live price for {symbol}: {live_price}")
        return live_price
    except Exception as e:
        logger.error(f"Error fetching live price for {symbol} for user {user.user_id}: {e}")
        return None

# ---------------------------------
# Routes
# ---------------------------------

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

# 1. Request Registration Link via Mobile Number
@app.route('/api/request_registration', methods=['POST'])
def request_registration():
    data = request.get_json()
    mobile_number = data.get('mobile_number')

    if not mobile_number:
        return jsonify({"success": False, "message": "Mobile number is required."}), 400

    # Check if maximum users reached
    user_count = User.query.count()
    if user_count >= 3:
        return jsonify({"success": False, "message": "Maximum number of users reached."}), 403

    # Generate a unique token
    token = generate_registration_token()
    expires_at = datetime.utcnow() + timedelta(minutes=15)  # Token valid for 15 minutes

    # Store the token in the database
    registration_token = RegistrationToken(
        token=token,
        mobile_number=mobile_number,
        expires_at=expires_at
    )
    db.session.add(registration_token)
    db.session.commit()

    # Send SMS with the registration link
    Thread(target=send_registration_sms, args=(mobile_number, token)).start()

    return jsonify({"success": True, "message": "Registration link sent via SMS."}), 200

# 2. Registration via Token
@app.route('/register/<token>', methods=['GET', 'POST'])
def register_via_token(token):
    registration_token = RegistrationToken.query.filter_by(token=token).first()

    if not registration_token:
        return "Invalid or expired registration link.", 400

    if registration_token.expires_at < datetime.utcnow():
        return "Registration link has expired.", 400

    if request.method == 'POST':
        user_id = request.form.get('user_id')
        broker = request.form.get('broker')
        api_key = request.form.get('api_key')
        username = request.form.get('username')
        password = request.form.get('password')
        totp_secret = request.form.get('totp_secret')
        default_quantity = request.form.get('default_quantity')

        # Validate inputs
        if not all([user_id, broker, api_key, username, password, totp_secret, default_quantity]):
            return "All fields are required.", 400

        if broker not in ['angel', 'shonnay']:
            return "Invalid broker selected.", 400

        existing_user = User.query.filter_by(user_id=user_id).first()
        if existing_user:
            return "User ID already exists.", 400

        # Hash the password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Create new user
        new_user = User(
            user_id=user_id,
            broker=broker,
            api_key=api_key,
            username=username,
            password_hash=hashed_password,
            totp_secret=totp_secret,
            default_quantity=int(default_quantity)
        )

        db.session.add(new_user)
        db.session.delete(registration_token)  # Invalidate the token after use
        db.session.commit()

        return redirect(url_for('index'))

    return render_template('register.html', token=token)

# 3. Login
@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    user_id_input = data.get('user_id')
    password_input = data.get('password')
    totp_input = data.get('totp')

    if not all([user_id_input, password_input, totp_input]):
        return jsonify({"success": False, "message": "All fields are required."}), 400

    user = User.query.filter_by(user_id=user_id_input).first()
    if user and user.check_password(password_input):
        # Verify TOTP
        totp = pyotp.TOTP(user.totp_secret)
        if totp.verify(totp_input):
            # Authenticate with SmartConnect
            try:
                smart_api = SmartConnect(api_key=user.api_key)
                data_smart = smart_api.generateSession(user.username, password_input, totp_input)
                
                if not data_smart or data_smart.get('status') == False:
                    logger.error(data_smart)
                    return jsonify({"success": False, "message": "SmartConnect login failed."}), 401
                
                # Extract tokens
                auth_token = data_smart['data']['jwtToken']
                refresh_token = data_smart['data']['refreshToken']
                
                # Update user with tokens
                user.auth_token = auth_token
                user.refresh_token = refresh_token
                db.session.commit()

                login_user(user)
                return jsonify({"success": True, "message": "Login successful."}), 200
            except Exception as e:
                logger.exception(f"SmartConnect login failed for user {user.user_id}: {e}")
                return jsonify({"success": False, "message": "SmartConnect login failed."}), 500
        else:
            return jsonify({"success": False, "message": "Invalid TOTP code."}), 401
    else:
        return jsonify({"success": False, "message": "Invalid credentials."}), 401

# 4. Logout
@app.route('/api/logout', methods=['POST'])
@login_required
def api_logout():
    current_user.auth_token = None
    current_user.refresh_token = None
    db.session.commit()
    logout_user()
    return jsonify({"success": True, "message": "Logged out successfully."}), 200

# 5. Get Profile
@app.route('/api/get_profile', methods=['GET'])
@login_required
def api_get_profile():
    profile = {
        "user_id": current_user.user_id,
        "broker": current_user.broker,
        "username": current_user.username,
        "api_key": current_user.api_key,
        "default_quantity": current_user.default_quantity
    }
    return jsonify({"success": True, "profile": profile}), 200

# 6. Auto Trade
auto_trade_flags = {}

@app.route('/api/auto_trade', methods=['POST'])
@login_required
def auto_trade():
    data = request.get_json()
    symbol = data.get('symbol')
    quantity = int(data.get('quantity'))
    condition = data.get('condition')  # 'Condition 1' or 'Condition 2'
    basis = data.get('basis')  # 'fixed', 'points', 'percentage'
    threshold_value = float(data.get('threshold_value'))
    reference_price = float(data.get('reference_price', 0))

    if not all([symbol, quantity > 0, condition, basis, threshold_value]):
        return jsonify({"success": False, "message": "Missing or invalid required fields."}), 400

    user_id = current_user.id

    # Initialize flag
    auto_trade_flags[user_id] = False

    def monitor_and_trade(user_id, symbol, quantity, condition, basis, threshold_value, reference_price):
        user = User.query.get(user_id)
        while not auto_trade_flags[user_id]:
            live_price = fetch_live_price(user, symbol)
            if live_price is None:
                time.sleep(5)
                continue

            trade_triggered = False
            if condition == "Condition 1":
                if basis == "fixed" and live_price >= threshold_value:
                    trade_triggered = True
                elif basis == "points" and live_price >= (reference_price + threshold_value):
                    trade_triggered = True
                elif basis == "percentage" and live_price >= (reference_price * (1 + threshold_value / 100)):
                    trade_triggered = True
            elif condition == "Condition 2":
                if basis == "fixed" and live_price > threshold_value:
                    trade_triggered = True
                elif basis == "points" and live_price > (reference_price + threshold_value):
                    trade_triggered = True
                elif basis == "percentage" and live_price > (reference_price * (1 + threshold_value / 100)):
                    trade_triggered = True

            if trade_triggered:
                order_details = {
                    "user_id": user_id,
                    "symbol": symbol,
                    "quantity": quantity,
                    "transactiontype": "BUY",
                    "price": live_price
                }
                place_order(order_details)
                break

            time.sleep(5)

    Thread(target=monitor_and_trade, args=(user_id, symbol, quantity, condition, basis, threshold_value, reference_price)).start()
    return jsonify({"success": True, "message": "Auto trading started successfully."}), 200

@app.route('/api/stop_auto_trade', methods=['POST'])
@login_required
def stop_auto_trade():
    user_id = current_user.id
    auto_trade_flags[user_id] = True
    return jsonify({"success": True, "message": "Auto trading stopped successfully."}), 200

# 7. Auto Stop-Loss Sell
stop_loss_flags = {}

@app.route('/api/auto_stoploss_sell', methods=['POST'])
@login_required
def auto_stoploss_sell():
    data = request.get_json()
    symbol = data.get('symbol')
    buy_price = float(data.get('buy_price'))
    quantity = int(data.get('quantity'))
    scenario = data.get('scenario')  # '1' or '2'
    stop_loss_type = data.get('stop_loss_type')  # 'percentage', 'points', 'fixed'
    fixed_stop_loss = data.get('fixed_stop_loss', None)

    if not all([symbol, buy_price > 0, quantity > 0, scenario, stop_loss_type]):
        return jsonify({"success": False, "message": "Missing or invalid required fields."}), 400

    user_id = current_user.id

    # Initialize flag
    stop_loss_flags[user_id] = False

    def monitor_and_sell(user_id, symbol, buy_price, quantity, scenario, stop_loss_type, fixed_stop_loss):
        user = User.query.get(user_id)
        highest_price = buy_price  # Track highest price for scenario 2
        stop_loss = None

        # Determine initial stop-loss based on type
        if stop_loss_type == 'percentage':
            stop_loss = buy_price * 0.95  # 5% below
        elif stop_loss_type == 'points':
            stop_loss = buy_price - 5  # 5 points below
        elif stop_loss_type == 'fixed' and fixed_stop_loss is not None:
            stop_loss = fixed_stop_loss
        else:
            logger.error("Invalid stop_loss_type or missing fixed_stop_loss value.")
            return

        while not stop_loss_flags[user_id]:
            live_price = fetch_live_price(user, symbol)
            if live_price is None:
                time.sleep(5)
                continue

            if scenario == "1":
                if live_price <= stop_loss:
                    # SELL
                    order_details = {
                        "user_id": user_id,
                        "symbol": symbol,
                        "quantity": quantity,
                        "transactiontype": "SELL",
                        "price": live_price
                    }
                    place_order(order_details)
                    break
            elif scenario == "2":
                if live_price > highest_price:
                    highest_price = live_price
                    # Adjust stop-loss based on type
                    if stop_loss_type == 'percentage':
                        stop_loss = highest_price * 0.95
                    elif stop_loss_type == 'points':
                        stop_loss = highest_price - 5
                    # 'fixed' remains unchanged

                if live_price <= stop_loss:
                    # SELL
                    order_details = {
                        "user_id": user_id,
                        "symbol": symbol,
                        "quantity": quantity,
                        "transactiontype": "SELL",
                        "price": live_price
                    }
                    place_order(order_details)
                    break

            time.sleep(5)

    Thread(target=monitor_and_sell, args=(user_id, symbol, buy_price, quantity, scenario, stop_loss_type, fixed_stop_loss)).start()
    return jsonify({"success": True, "message": "Trailing stop-loss monitoring started."}), 200

@app.route('/api/stop_auto_stoploss_sell', methods=['POST'])
@login_required
def stop_auto_stoploss_sell():
    user_id = current_user.id
    stop_loss_flags[user_id] = True
    return jsonify({"success": True, "message": "Trailing stop-loss monitoring stopped."}), 200

# 8. Get All Trades
@app.route('/api/get_all_trades', methods=['GET'])
@login_required
def get_all_trades():
    trades = Trade.query.all()
    trades_data = []
    for trade in trades:
        trades_data.append({
            "trade_id": trade.trade_id,
            "user_id": User.query.get(trade.user_id).user_id,
            "symbol": trade.symbol,
            "quantity": trade.quantity,
            "transaction_type": trade.transaction_type,
            "price": trade.price,
            "timestamp": trade.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        })
    return jsonify({"success": True, "trades": trades_data}), 200

# 9. Fetch Live Prices for Chart
@app.route('/api/live_price', methods=['GET'])
@login_required
def live_price():
    symbol = request.args.get('symbol')
    if not symbol:
        return jsonify({"success": False, "message": "Symbol is required."}), 400

    user = current_user
    live_price = fetch_live_price(user, symbol)

    if live_price is None:
        return jsonify({"success": False, "message": "Failed to fetch live price."}), 500

    return jsonify({"success": True, "live_price": live_price}), 200

# ---------------------------------
# Run Flask App
# ---------------------------------

if __name__ == "__main__":
    app.run(debug=True)
