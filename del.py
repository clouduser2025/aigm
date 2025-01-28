import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

# Initialize Flask App
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///multi_broker_trade.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy
db = SQLAlchemy(app)

# Define the Models
class TradingUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    broker = db.Column(db.String(20), nullable=False)     # 'angel' or 'shonnay'
    api_key = db.Column(db.String(128), nullable=False)   # API key for the broker
    totp_token = db.Column(db.String(64), nullable=True)  # Optional TOTP for Angel broker
    default_quantity = db.Column(db.Integer, default=1)   # Default trade quantity
    trades = db.relationship("Trade", backref="trading_user", lazy=True)

class Trade(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    symbol = db.Column(db.String(20), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    transaction_type = db.Column(db.String(10), nullable=False)  # 'BUY' or 'SELL'
    price = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.now())
    broker_order_id = db.Column(db.String(50), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('trading_user.id'), nullable=False)

# Check and Create Database
db_path = "multi_broker_trade.db"
if os.path.exists(db_path):
    os.remove(db_path)
    print("Database removed successfully.")

# Create a new database
with app.app_context():
    db.create_all()
    print("New database and tables created successfully.")
