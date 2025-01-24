# app.py
import os
import uuid
import pyotp
from datetime import datetime, timedelta
from threading import Thread, Lock

from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from logzero import logger

###############################################################################
#                         Flask App Initialization
###############################################################################
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'yoursecretkey')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///trading_dashboard.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

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

# Create tables if not exist
with app.app_context():
    db.create_all()

###############################################################################
#                     Helper Functions
###############################################################################
def generate_totp(secret):
    try:
        return pyotp.TOTP(secret).now()
    except Exception as e:
        logger.error("Invalid TOTP Token.")
        raise e

def generate_registration_token():
    return str(uuid.uuid4())

###############################################################################
#                           Flask Routes
###############################################################################
@app.route('/')
def index():
    return render_template('index.html')

# 1. Request Registration
@app.route('/api/request_registration', methods=['POST'])
def request_registration():
    data = request.json
    mobile_number = data.get('mobile_number')
    if not mobile_number:
        return jsonify({"success": False, "message": "Mobile number is required."}), 400

    token = generate_registration_token()
    expires = datetime.utcnow() + timedelta(minutes=15)
    reg = RegistrationToken(token=token, mobile_number=mobile_number, expires_at=expires)
    db.session.add(reg)
    db.session.commit()

    return jsonify({"success": True, "message": "Registration link created."}), 200

# 2. Registration
@app.route('/register/<token>', methods=['GET', 'POST'])
def register_via_token(token):
    reg = RegistrationToken.query.filter_by(token=token).first()
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

        if not all([user_id, broker, api_key, username, password, totp_token, default_quantity]):
            return "All fields are required.", 400

        pwd_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(user_id=user_id, broker=broker, api_key=api_key,
                        username=username, password_hash=pwd_hash,
                        totp_token=totp_token, default_quantity=int(default_quantity))
        db.session.add(new_user)
        db.session.delete(reg)
        db.session.commit()
        return redirect(url_for('index'))

    return render_template('register.html', token=token)

# 3. Get All Trades
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

###############################################################################
#                      Run the Flask App
###############################################################################
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
