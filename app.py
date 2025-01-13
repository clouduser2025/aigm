# ========================================
# BACKEND (app.py)
# ========================================

from flask import Flask, request, jsonify, render_template, url_for
import pyotp
import time
from threading import Thread
from logzero import logger
import http.client  # For making HTTP requests (if needed)
import json         # For parsing and generating JSON data

# -------------------------------------------------------------------------
# SMART API (Angel One)
# -------------------------------------------------------------------------
# pip install smartapi-python
try:
    from SmartApi.smartConnect import SmartConnect
except ImportError:
    logger.warning("SmartConnect library not found; only for demonstration.")
    SmartConnect = None

# Replace these with your actual credentials
API_KEY = 'y2gLEdxZ'
USERNAME = 'A62128571'
PASSWORD = '0852'


# If you have a TOTP secret from Angel One, provide it here;
# otherwise, your `login_to_api()` might rely on a user-provided TOTP each time.
# totp_secret = 'YOUR_TOTP_SECRET'

app = Flask(__name__)

# In-memory references
smartApi = None
authToken = None
refreshToken = None

# For demonstration, we create placeholders. In real usage, instantiate properly.
if SmartConnect:
    smartApi = SmartConnect(api_key=API_KEY)

# We track a global flag for stopping the trailing stop-loss thread
stop_trailing_stop_flag = [False]  # using list for mutable reference

# -------------------------------------------------------------------------
# HELPER FUNCTIONS
# -------------------------------------------------------------------------
def generate_totp(token):
    """Generate TOTP code using a provided token (i.e., from QR code)."""
    try:
        totp = pyotp.TOTP(token).now()
        return totp
    except Exception as e:
        logger.error("Invalid Token: The provided token is not valid.")
        raise e

def login_to_api(username, password, token):
    """
    Log in to the Smart API using credentials and a TOTP.
    Returns (authToken, refreshToken) on success, or None on failure.
    """
    global smartApi
    if smartApi is None:
        logger.warning("No SmartConnect instance available; skipping real login.")
        # Return mock tokens for demo
        return "demoAuthToken", "demoRefreshToken"

    try:
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
    Place an order with given order parameters (dict).
    Returns the order ID on success, or None on failure.
    """
    global smartApi
    if smartApi is None:
        logger.warning("No SmartConnect instance available; skipping real placeOrder.")
        return "demoOrderID"

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
    global smartApi
    if smartApi is None:
        logger.warning("No SmartConnect instance available; skipping real gttCreateRule.")
        return "demoGTTID"

    try:
        rule_id = smartApi.gttCreateRule(gttCreateParams)
        logger.info(f"The GTT rule id is: {rule_id}")
        return rule_id
    except Exception as e:
        logger.exception(f"GTT Rule creation failed: {e}")
        return None

def list_gtt_rules():
    """ List GTT rules. Returns the GTT list data, or None on failure."""
    global smartApi
    if smartApi is None:
        logger.warning("No SmartConnect instance available; skipping real gttLists.")
        return {"status": True, "message": "Demo GTT List", "data": []}

    try:
        status = ["FORALL"]
        page = 1
        count = 10
        gtt_list = smartApi.gttLists(status, page, count)
        return gtt_list
    except Exception as e:
        logger.exception(f"GTT Rule List failed: {e}")
        return None

def fetch_live_price(symbol):
    """
    Fetches live price for a symbol from the Smart API or returns a dummy price for demo.
    """
    global smartApi
    if smartApi is None:
        logger.warning(f"No SmartConnect instance; returning a dummy live price for {symbol}.")
        import random
        return 100 + random.uniform(-10, 10)  # random around 100 for demo

    try:
        # example: smartApi.ltpData("NSE", "SBIN")
        # Note: The arguments might vary depending on the library version
        ltp_data = smartApi.ltpData("NSE", symbol)
        return float(ltp_data['data']['ltp'])
    except Exception as e:
        logger.error(f"Error fetching live price for {symbol}: {e}")
        return None


# -------------------------------------------------------------------------
# FLASK ROUTES
# -------------------------------------------------------------------------
@app.route('/', methods=['GET'])
def index():
    """
    Serves the main HTML page for the web application.
    """
    return render_template('index.html')


# 1. LOGIN
@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    username_input = data.get('username')
    password_input = data.get('password')
    totp_input = data.get('totp')

    global authToken, refreshToken
    tokens = login_to_api(username_input, password_input, totp_input)
    if tokens:
        authToken, refreshToken = tokens
        return jsonify({
            "success": True,
            "message": "Login Successfully",
            "authToken": authToken,
            "refreshToken": refreshToken
        })
    else:
        return jsonify({"success": False, "message": "Login Failed"})

# 2. PLACE ORDER
@app.route('/api/place_order', methods=['POST'])
def api_place_order():
    data = request.get_json()
    order_params = data.get('orderParams', {})
    order_id = place_order(order_params)
    if order_id:
        return jsonify({"success": True, "orderid": order_id})
    else:
        return jsonify({"success": False, "error": "Order placement failed."})

# 3. CREATE GTT
@app.route('/api/create_gtt_rule', methods=['POST'])
def api_create_gtt_rule():
    data = request.get_json()
    gtt_params = data.get('gttParams', {})
    rule_id = create_gtt_rule(gtt_params)
    if rule_id:
        return jsonify({"success": True, "rule_id": rule_id})
    else:
        return jsonify({"success": False, "error": "GTT Rule creation failed."})

# 4. LIST GTT
@app.route('/api/list_gtt_rules', methods=['POST'])
def api_list_gtt_rules():
    gtt_list_data = list_gtt_rules()
    if gtt_list_data:
        return jsonify({"success": True, "gtt_list": gtt_list_data})
    else:
        return jsonify({"success": False, "error": "GTT listing failed."})

# 5. MANUAL TRADE
@app.route('/api/manual_trade', methods=['POST'])
def manual_trade():
    data = request.get_json()
    symbol = data.get('symbol')
    target_price = data.get('target_price', 0)
    quantity = int(data.get('quantity', 1))
    transaction_type = data.get('transaction_type', "BUY")

    # For demonstration, we pass a minimal orderParams
    order_id = place_order({
        "tradingsymbol": symbol,
        "price": target_price,
        "quantity": quantity,
        "transactiontype": transaction_type,
        "exchange": "NSE",
        "producttype": "INTRADAY",
        "ordertype": "MARKET",  # or "LIMIT" if you'd prefer
    })
    if order_id:
        return jsonify({"success": True, "message": f"Manual order placed. ID: {order_id}"})
    else:
        return jsonify({"success": False, "message": "Manual trade failed."})

# 6. GET PROFILE
@app.route('/api/get_profile', methods=['POST'])
def api_get_profile():
    data = request.get_json()
    refresh_token_input = data.get("refreshToken")

    if not refresh_token_input:
        return jsonify({"success": False, "error": "Missing refreshToken"})

    try:
        # Use the SmartAPI instance to fetch profile
        profile_data = smartApi.getProfile(refresh_token_input)

        if not profile_data or not profile_data.get('status'):
            raise Exception(profile_data.get('message', 'Unknown error fetching profile'))

        profile = profile_data.get('data', {})
        return jsonify({"success": True, "profile": profile})

    except Exception as e:
        logger.error(f"Failed to fetch profile: {e}")
        return jsonify({"success": False, "error": str(e)})


# 7. AUTO TRADE BUY (Condition 1 & 2)
stop_auto_trade_flag = [False]

@app.route('/api/auto_trade', methods=['POST'])
def auto_trade():
    data = request.get_json()
    symbol = data.get('symbol')
    quantity = int(data.get('quantity'))
    condition = data.get('condition')
    basis = data.get('basis')
    threshold_value = float(data.get('threshold_value'))
    reference_price = float(data.get('reference_price', 0))

    stop_auto_trade_flag[0] = False

    def monitor_and_trade():
        try:
            while not stop_auto_trade_flag[0]:
                live_price = fetch_live_price(symbol)
                if live_price is None:
                    time.sleep(5)
                    continue

                # Simplified logic for demonstration:
                if condition == "Condition 1":
                    if basis == "fixed" and live_price >= threshold_value:
                        place_order({"tradingsymbol": symbol, "price": live_price, "quantity": quantity,
                                     "transactiontype": "BUY", "exchange": "NSE", "producttype": "INTRADAY",
                                     "ordertype": "MARKET"})
                        break
                    elif basis == "points" and live_price >= (live_price + threshold_value):
                        # Not a typical logic, you might want reference_price + threshold_value
                        break
                    elif basis == "percentage" and live_price >= live_price * (1 + threshold_value / 100):
                        break

                elif condition == "Condition 2":
                    if basis == "fixed" and live_price > threshold_value:
                        place_order({"tradingsymbol": symbol, "price": live_price, "quantity": quantity,
                                     "transactiontype": "BUY", "exchange": "NSE", "producttype": "INTRADAY",
                                     "ordertype": "MARKET"})
                        break
                    elif basis == "points" and live_price > reference_price + threshold_value:
                        place_order({"tradingsymbol": symbol, "price": live_price, "quantity": quantity,
                                     "transactiontype": "BUY", "exchange": "NSE", "producttype": "INTRADAY",
                                     "ordertype": "MARKET"})
                        break
                    elif basis == "percentage" and live_price > reference_price * (1 + threshold_value / 100):
                        place_order({"tradingsymbol": symbol, "price": live_price, "quantity": quantity,
                                     "transactiontype": "BUY", "exchange": "NSE", "producttype": "INTRADAY",
                                     "ordertype": "MARKET"})
                        break

                time.sleep(5)
        except Exception as e:
            logger.error(f"Error in auto-trading: {e}")

    Thread(target=monitor_and_trade).start()
    return jsonify({"success": True, "message": "Auto trading started successfully."})

@app.route('/api/stop_auto_trade', methods=['POST'])
def stop_auto_trade():
    stop_auto_trade_flag[0] = True
    return jsonify({"success": True, "message": "Auto trading stopped successfully."})

@app.route('/api/auto_stoploss_sell', methods=['POST'])
def auto_stoploss_sell():
    """
    Enhanced Stop-Loss Mechanism:
    - Option 1: 5% less of the buy price or highest price observed (default).
    - Option 2: 5 points less of the buy price or highest price observed.
    - Option 3: User-specified fixed stop-loss value.

    The stop-loss adjusts dynamically in Scenario 2 (trailing).
    """
    data = request.get_json()
    symbol = data.get('symbol')
    buy_price = float(data.get('buy_price'))
    quantity = int(data.get('quantity'))
    scenario = data.get('scenario')
    stop_loss_type = data.get('stop_loss_type', 'percentage')  # 'percentage', 'points', or 'fixed'
    fixed_stop_loss = data.get('fixed_stop_loss', None)  # Only required for 'fixed'

    # Reset the global stop-flag
    stop_trailing_stop_flag[0] = False

    def monitor_and_sell():
        try:
            highest_price = buy_price  # Track the highest if scenario=2
            stop_loss = None  # Initialize stop-loss

            # Determine initial stop-loss based on the type
            if stop_loss_type == 'percentage':
                stop_loss = buy_price * 0.95  # 5% less
            elif stop_loss_type == 'points':
                stop_loss = buy_price - 5  # 5 points less
            elif stop_loss_type == 'fixed' and fixed_stop_loss is not None:
                stop_loss = fixed_stop_loss
            else:
                raise ValueError("Invalid stop_loss_type or missing fixed_stop_loss value")

            while not stop_trailing_stop_flag[0]:
                live_price = fetch_live_price(symbol)
                if live_price is None:
                    time.sleep(5)
                    continue

                # SCENARIO 1: Price does not rise above buy price
                if scenario == "1":
                    if live_price <= stop_loss:
                        # SELL
                        place_order({
                            "tradingsymbol": symbol,
                            "price": live_price,
                            "quantity": quantity,
                            "transactiontype": "SELL",
                            "exchange": "NSE",
                            "producttype": "INTRADAY",
                            "ordertype": "MARKET"
                        })
                        break

                # SCENARIO 2: Price rises, adjust stop-loss dynamically
                elif scenario == "2":
                    if live_price > highest_price:
                        highest_price = live_price
                        # Recalculate stop-loss based on type
                        if stop_loss_type == 'percentage':
                            stop_loss = highest_price * 0.95
                        elif stop_loss_type == 'points':
                            stop_loss = highest_price - 5
                        elif stop_loss_type == 'fixed':
                            pass  # Fixed stop-loss remains constant

                    if live_price <= stop_loss:
                        # SELL
                        place_order({
                            "tradingsymbol": symbol,
                            "price": live_price,
                            "quantity": quantity,
                            "transactiontype": "SELL",
                            "exchange": "NSE",
                            "producttype": "INTRADAY",
                            "ordertype": "MARKET"
                        })
                        break

                time.sleep(5)
        except Exception as e:
            logger.error(f"Error in auto stop-loss trailing: {e}")

    Thread(target=monitor_and_sell).start()
    return jsonify({"success": True, "message": "Trailing stop-loss monitoring started."})


@app.route('/api/stop_auto_stoploss_sell', methods=['POST'])
def stop_auto_stoploss_sell():
    stop_trailing_stop_flag[0] = True
    return jsonify({"success": True, "message": "Trailing stop-loss monitoring stopped."})

# -------------------------------------------------------------------------
# RUN FLASK
# -------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(debug=True)
