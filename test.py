from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_socketio import SocketIO, emit
from dotenv import load_dotenv
import pyotp
import os
import time
import threading
from datetime import datetime, timedelta
import secrets
from SmartApi import SmartConnect
from twilio.rest import Client

###############################################################################
#                         Flask App Initialization
###############################################################################
app = Flask(__name__, template_folder='.')

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'yoursecretkey')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///trading_dashboard.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
socketio = SocketIO(app)

###############################################################################
#                         Database Models
###############################################################################
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(150), unique=True, nullable=False)
    broker = db.Column(db.String(50), nullable=False)
    api_key = db.Column(db.String(150), nullable=False)
    username = db.Column(db.String(150), nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)
    totp_token = db.Column(db.String(150), nullable=False)
    default_quantity = db.Column(db.Integer, nullable=False, default=1)

    trades = db.relationship('Trade', backref='owner', lazy=True)


class Trade(db.Model):
    __tablename__ = 'trades'
    id = db.Column(db.Integer, primary_key=True)
    trade_id = db.Column(db.String(50), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    symbol = db.Column(db.String(50), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    transaction_type = db.Column(db.String(10), nullable=False)
    price = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class RegistrationToken(db.Model):
    __tablename__ = 'registration_tokens'
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(100), unique=True, nullable=False)
    mobile_number = db.Column(db.String(20), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)


# Create tables if they do not exist
with app.app_context():
    db.create_all()

###############################################################################
#                         Environment Variables
###############################################################################
load_dotenv()

API_KEY = os.getenv("API_KEY")
CLIENT_CODE = os.getenv("CLIENT_CODE")
CLIENT_PASSWORD = os.getenv("CLIENT_PASSWORD")
TOTP_SECRET = os.getenv("TOTP_SECRET")

TWILIO_ACCOUNT_SID = os.getenv('TWILIO_ACCOUNT_SID')
TWILIO_AUTH_TOKEN = os.getenv('TWILIO_AUTH_TOKEN')
TWILIO_PHONE_NUMBER = os.getenv('TWILIO_PHONE_NUMBER')
twilio_client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
def send_sms(to, message):
    try:
        message = twilio_client.messages.create(
            body=message,
            from_=TWILIO_PHONE_NUMBER,
            to=to
        )
        print(f"SMS sent successfully: SID {message.sid}")
        return True
    except Exception as e:
        print(f"Failed to send SMS: {e}")
        return False

# Global variables for real-time updates
exchange, tradingsymbol, symboltoken = None, None, None
live_chart_data = []  # Store live price data for historical charting

###############################################################################
#                         Angel API Login Function
###############################################################################
def AngelLogin():
    try:
        obj = SmartConnect(api_key=API_KEY)
        data = obj.generateSession(CLIENT_CODE, CLIENT_PASSWORD, pyotp.TOTP(TOTP_SECRET).now())
        print("Successfully logged in.")
        return obj
    except Exception as e:
        print(f"Error during login: {e}")
        raise e

###############################################################################
#                         Utility Functions
###############################################################################
# Generate a unique registration token
def generate_registration_token():
    return secrets.token_urlsafe(32)

###############################################################################
#                         Flask Routes
###############################################################################

@app.route('/')
def home():
    return render_template('index.html')


@app.route('/get_data', methods=['POST'])
def get_data():
    global exchange, tradingsymbol, symboltoken
    exchange = request.form['exchange'].upper()
    tradingsymbol = request.form['tradingsymbol'].upper()
    symboltoken = request.form['symboltoken']

    try:
        obj = AngelLogin()
        # Fetch trading balance
        rms_data = obj.rmsLimit()
        if rms_data['status']:
            balance_data = rms_data['data']
            available_cash = balance_data.get('availablecash', 'N/A')
            net = balance_data.get('net', 'N/A')
        else:
            return f"Error fetching balance: {rms_data.get('message')}"

        # Fetch initial live price
        ltp_data = obj.ltpData(exchange, tradingsymbol, symboltoken)
        if ltp_data['status']:
            live_price = ltp_data['data']['ltp']
        else:
            live_price = "Error fetching live price: " + ltp_data.get('message', 'Unknown error')

        return render_template(
            'result.html',
            available_cash=available_cash,
            net=net,
            tradingsymbol=tradingsymbol,
            live_price=live_price
        )
    except Exception as e:
        return f"An error occurred: {e}"


@app.route('/chart', methods=['POST', 'GET'])
def chart():
    """
    Render the TradingView chart page with the user's input symbol and exchange.
    """
    if request.method == 'POST':
        global exchange, tradingsymbol
        exchange = request.form.get('exchange', '').upper()
        tradingsymbol = request.form.get('tradingsymbol', '').upper()

    # Render the chart page dynamically with user input
    return render_template('chart.html', tradingsymbol=tradingsymbol, exchange=exchange)


@app.route('/chart_data')
def chart_data():
    """Provide live chart data as JSON."""
    return {"data": live_chart_data}


###############################################################################
#                         Emit Live Price Data
###############################################################################
def emit_live_data():
    global live_chart_data
    obj = AngelLogin()
    while True:
        try:
            if tradingsymbol and symboltoken and exchange:
                ltp_data = obj.ltpData(exchange, tradingsymbol, symboltoken)
                if ltp_data['status']:
                    live_price = ltp_data['data']['ltp']
                    current_time = int(time.time())
                    live_chart_data.append({'time': current_time, 'value': live_price})

                    # Keep chart data limited to last 100 entries
                    if len(live_chart_data) > 100:
                        live_chart_data.pop(0)

                    # Emit the live price
                    socketio.emit('live_price', {'time': current_time, 'price': live_price})
        except Exception as e:
            print(f"Error fetching live price: {e}")
        time.sleep(5)


###############################################################################
#                         Registration API
###############################################################################
@app.route('/api/request_registration', methods=['POST'])
def request_registration():
    data = request.json
    mobile_number = data.get('mobile_number')
    if not mobile_number:
        return jsonify({"success": False, "message": "Mobile number is required."}), 400

    # Generate token and expiration time
    token = generate_registration_token()
    expires = datetime.utcnow() + timedelta(minutes=15)

    # Save token to the database
    reg = RegistrationToken(token=token, mobile_number=mobile_number, expires_at=expires)
    db.session.add(reg)
    db.session.commit()

    # Send SMS with the registration link
    registration_link = f"http://127.0.0.1:5000/register/{token}"
    sms_message = f"Your registration link is: {registration_link}"

    sms_status = send_sms(mobile_number, sms_message)

    if sms_status:
        return jsonify({"success": True, "message": "Registration link created and SMS sent.", "token": token}), 200
    else:
        return jsonify({"success": False, "message": "Registration link created but failed to send SMS.", "token": token}), 500



@app.route('/register/<token>', methods=['GET', 'POST'])
def register_via_token(token):
    reg = RegistrationToken.query.filter_by(token=token).first()

    # Validate token existence and expiration
    if not reg:
        return "Invalid or expired registration link.", 400
    if reg.expires_at < datetime.utcnow():
        return "Registration link expired.", 400

    if request.method == 'POST':
        form = request.form
        user_id = form.get('user_id')
        broker = form.get('broker')
        api_key = form.get('api_key')
        username = form.get('username')
        password = form.get('password')
        totp_token = form.get('totp_token')
        default_quantity = form.get('default_quantity')

        # Validate all fields
        if not all([user_id, broker, api_key, username, password, totp_token, default_quantity]):
            return "All fields are required.", 400

        # Hash the password
        pwd_hash = bcrypt.generate_password_hash(password).decode('utf-8')

        # Create a new user and save to the database
        new_user = User(
            user_id=user_id,
            broker=broker,
            api_key=api_key,
            username=username,
            password_hash=pwd_hash,
            totp_token=totp_token,
            default_quantity=int(default_quantity)
        )
        db.session.add(new_user)

        # Delete the registration token after successful registration
        db.session.delete(reg)
        db.session.commit()

        return redirect(url_for('home'))

    return render_template('register.html', token=token)


###############################################################################
#                         APIs for Users and Trades
###############################################################################
@app.route('/api/get_all_trades', methods=['GET'])
def get_all_trades():
    trades = Trade.query.all()
    data = []
    for t in trades:
        data.append({
            "trade_id": t.trade_id,
            "user_id": t.owner.user_id,
            "broker": t.owner.broker,
            "symbol": t.symbol,
            "quantity": t.quantity,
            "transaction_type": t.transaction_type,
            "price": t.price,
            "timestamp": t.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        })
    return jsonify({"success": True, "trades": data}), 200


@app.route('/api/get_all_users', methods=['GET'])
def get_all_users():
    users = User.query.all()
    data = []
    for u in users:
        data.append({
            "user_id": u.user_id,
            "broker": u.broker,
            "username": u.username,
            "default_quantity": u.default_quantity,
            "totp_token": u.totp_token
        })
    return jsonify({"success": True, "users": data}), 200

@app.route('/users')
def users():
    """Render the list of all users."""
    users = User.query.all()
    return render_template('users.html', users=users)


@app.route('/trades')
def trades():
    """Render the list of all trades."""
    trades = Trade.query.all()
    return render_template('trades.html', trades=trades)


@app.route('/request_registration_form')
def request_registration_form():
    """Render the request registration form."""
    return render_template('request_registration.html')

###############################################################################
#                      Run the Flask App
###############################################################################
if __name__ == '__main__':
    # Start a thread for live price updates
    thread = threading.Thread(target=emit_live_data)
    thread.daemon = True
    thread.start()

    socketio.run(app, debug=True)
