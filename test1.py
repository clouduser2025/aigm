from flask import Flask, render_template, request
from SmartApi import SmartConnect
import pyotp
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

API_KEY = os.getenv("API_KEY")
CLIENT_CODE = os.getenv("CLIENT_CODE")
CLIENT_PASSWORD = os.getenv("CLIENT_PASSWORD")
TOTP_SECRET = os.getenv("TOTP_SECRET")

app = Flask(__name__)

# Login function
def AngelLogin():
    obj = SmartConnect(api_key=API_KEY)
    data = obj.generateSession(CLIENT_CODE, CLIENT_PASSWORD, pyotp.TOTP(TOTP_SECRET).now())
    return obj

# Flask Routes
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/get_data', methods=['POST'])
def get_data():
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
        
        # Fetch live price
        ltp_data = obj.ltpData(exchange, tradingsymbol, symboltoken)
        if ltp_data['status']:
            live_price = ltp_data['data']['ltp']
        else:
            live_price = "Error fetching live price: " + ltp_data.get('message', 'Unknown error')
        
        return render_template(
            'result.html', 
            available_cash=available_cash, 
            net=net, 
            live_price=live_price, 
            tradingsymbol=tradingsymbol
        )
    except Exception as e:
        return f"An error occurred: {e}"

if __name__ == '__main__':
    app.run(debug=True)
