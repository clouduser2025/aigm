from flask import Flask, request, jsonify, render_template, url_for
import pyotp
from logzero import logger
import http.client  # For making HTTP requests (if needed)
import json         # For parsing and generating JSON data

# -------------------------------------------------------------------------
# SMART API (Angel One)
# -------------------------------------------------------------------------
# Ensure you install the correct SmartAPI library:
# pip install smartapi-python
from SmartApi.smartConnect import SmartConnect

# Replace these with your actual credentials
api_key = 'y2gLEdxZ'
username = 'A62128571'
pwd = '0852'

# If you have a TOTP secret from Angel One, provide it here;
# otherwise, your `login_to_api()` might rely on a user-provided TOTP each time.
# totp_secret = 'YOUR_TOTP_SECRET'

smartApi = SmartConnect(api_key=api_key)

app = Flask(__name__)

# -------------------------------------------------------------------------
# HELPER FUNCTIONS
# -------------------------------------------------------------------------
def generate_totp(token):
    """
    Generate TOTP code using a provided token (i.e., the string/secret from your QR code).
    """
    try:
        totp = pyotp.TOTP(token).now()
        return totp
    except Exception as e:
        logger.error("Invalid Token: The provided token is not valid.")
        raise e

def login_to_api(username, password, token):
    """
    Log in to the Smart API using credentials and a TOTP.
    Returns (authToken, refreshToken) upon success, or None if fails.
    """
    try:
        # Generate the 6-digit TOTP from the secret
        totp_code = generate_totp(token)
        data = smartApi.generateSession(username, password, totp_code)
        
        if not data or data.get('status') == False:
            logger.error(data)
            return None
        
        # Extract tokens
        auth_token = data['data']['jwtToken']
        refresh_token = data['data']['refreshToken']
        return auth_token, refresh_token
    except Exception as e:
        logger.exception(f"Login failed: {e}")
        return None

def place_order(orderparams):
    """
    Place an order with given order parameters.
    Returns the order ID on success, or None on failure.
    """
    try:
        orderid = smartApi.placeOrder(orderparams)
        logger.info(f"Order placed successfully: {orderid}")
        return orderid
    except Exception as e:
        logger.exception(f"Order placement failed: {e}")
        return None

def create_gtt_rule(gttCreateParams):
    """
    Create a GTT rule with the given parameters.
    Returns the GTT rule ID on success, or None on failure.
    """
    try:
        rule_id = smartApi.gttCreateRule(gttCreateParams)
        logger.info(f"The GTT rule id is: {rule_id}")
        return rule_id
    except Exception as e:
        logger.exception(f"GTT Rule creation failed: {e}")
        return None

def list_gtt_rules():
    """
    List GTT rules. Returns the GTT list data, or None on failure.
    """
    try:
        status = ["FORALL"]
        page = 1
        count = 10
        gtt_list = smartApi.gttLists(status, page, count)
        return gtt_list
    except Exception as e:
        logger.exception(f"GTT Rule List failed: {e}")
        return None


# -------------------------------------------------------------------------
# FLASK ROUTES
# -------------------------------------------------------------------------
@app.route('/', methods=['GET'])
def index():
    """
    Serves the main HTML page (index.html) from the 'templates' directory.
    """
    return render_template('index.html')


# 1. LOGIN
@app.route('/api/login', methods=['POST'])
def api_login():
    """
    API endpoint for logging in using provided credentials and TOTP token.
    """
    data = request.get_json()
    username_input = data.get('username')
    password_input = data.get('password')
    totp_input = data.get('totp')

    auth_tokens = login_to_api(username_input, password_input, totp_input)
    if auth_tokens:
        return jsonify({
            "success": True,
            "message": "Login Successfully",
            "authToken": auth_tokens[0],
            "refreshToken": auth_tokens[1]
        })
    else:
        return jsonify({"success": False, "message": "Login Failed"})


# 2. PLACE ORDER
@app.route('/api/place_order', methods=['POST'])
def api_place_order():
    """
    API endpoint to place an order.
    """
    data = request.get_json()
    order_params = data.get('orderParams', {})
    # Typically you'd re-auth or ensure the session is valid. 
    order_id = place_order(order_params)
    if order_id:
        return jsonify({"success": True, "orderid": order_id})
    else:
        return jsonify({"success": False, "error": "Order placement failed."})

from threading import Thread
import time

# Monitor price and execute trades
def auto_trade_logic(symbol, thresholds, mode, auth_token):
    """
    Monitors the price of a given symbol and places orders based on thresholds.
    :param symbol: Symbol to monitor (e.g., NIFTY50).
    :param thresholds: Dictionary with stop_loss and take_profit values.
    :param mode: AUTO or MANUAL mode.
    :param auth_token: Auth token for placing trades.
    """
    try:
        while True:
            # Fetch the latest price using SmartAPI's LTP function
            ltp_data = smartApi.ltpData('NFO', symbol)
            current_price = float(ltp_data['data']['ltp'])

            if current_price <= thresholds['stop_loss']:
                logger.info(f"Stop-loss triggered. Selling {symbol} at {current_price}")
                place_order({
                    "variety": "NORMAL",
                    "tradingsymbol": symbol,
                    "transactiontype": "SELL",
                    "exchange": "NFO",
                    "ordertype": "MARKET",
                    "producttype": "INTRADAY",
                    "quantity": thresholds['quantity'],
                    "price": current_price
                })
                break

            if current_price >= thresholds['take_profit']:
                logger.info(f"Take-profit triggered. Selling {symbol} at {current_price}")
                place_order({
                    "variety": "NORMAL",
                    "tradingsymbol": symbol,
                    "transactiontype": "SELL",
                    "exchange": "NFO",
                    "ordertype": "MARKET",
                    "producttype": "INTRADAY",
                    "quantity": thresholds['quantity'],
                    "price": current_price
                })
                break

            # Sleep for a few seconds before checking again
            time.sleep(5)
    except Exception as e:
        logger.error(f"Error in auto-trade logic: {e}")

# API to start auto-trading
@app.route('/api/start_auto_trade', methods=['POST'])
def start_auto_trade():
    """
    Starts the auto-trade logic with the given parameters.
    """
    data = request.get_json()
    symbol = data.get('symbol')
    initial_price = float(data.get('initial_price'))
    mode = data.get('mode', 'AUTO')
    quantity = int(data.get('quantity', 1))

    thresholds = {
        'stop_loss': initial_price * 0.9,  # 10% below initial price
        'take_profit': initial_price * 1.15,  # 15% above initial price
        'quantity': quantity
    }

    thread = Thread(target=auto_trade_logic, args=(symbol, thresholds, mode, authToken))
    thread.start()

    return jsonify({"success": True, "message": f"Started auto-trading for {symbol}"})

# API to stop auto-trading
@app.route('/api/stop_auto_trade', methods=['POST'])
def stop_auto_trade():
    """
    Stops the auto-trade logic (if running).
    """
    # This can be implemented with a flag or by killing the thread gracefully.
    return jsonify({"success": True, "message": "Auto-trading stopped"})


# 3. CREATE GTT RULE
@app.route('/api/create_gtt_rule', methods=['POST'])
def api_create_gtt_rule():
    """
    API endpoint to create a GTT rule.
    """
    data = request.get_json()
    gtt_params = data.get('gttParams', {})

    rule_id = create_gtt_rule(gtt_params)
    if rule_id:
        return jsonify({"success": True, "rule_id": rule_id})
    else:
        return jsonify({"success": False, "error": "GTT Rule creation failed."})


# 4. LIST GTT RULES
@app.route('/api/list_gtt_rules', methods=['POST'])
def api_list_gtt_rules():
    """
    API endpoint to list GTT rules.
    """
    gtt_list_data = list_gtt_rules()
    if gtt_list_data:
        return jsonify({"success": True, "gtt_list": gtt_list_data})
    else:
        return jsonify({"success": False, "error": "GTT listing failed."})


# 7. GET PROFILE
@app.route('/api/get_profile', methods=['POST'])
def api_get_profile():
    """
    API endpoint to fetch user profile using SmartAPI's getProfile() method.
    """
    data = request.get_json()
    refresh_token_input = data.get("refreshToken")

    if not refresh_token_input:
        return jsonify({"success": False, "error": "Missing refreshToken"})

    try:
        # Attempt to fetch user profile
        profile_data = smartApi.getProfile(refresh_token_input)
        if not profile_data or not profile_data.get('status'):
            raise Exception(profile_data.get('message', 'Unknown error fetching profile'))

        profile = profile_data.get('data', {})
        return jsonify({"success": True, "profile": profile})
    except Exception as e:
        logger.error(f"Failed to fetch profile: {e}")
        return jsonify({"success": False, "error": str(e)})


# -------------------------------------------------------------------------
# RUN FLASK (Development Only)
# -------------------------------------------------------------------------
if __name__ == "__main__":
    # In production, use a production-ready WSGI server like gunicorn.
    app.run(debug=True)
