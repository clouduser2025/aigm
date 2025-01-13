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
# Global flag to manage auto-trading
stop_auto_trade_flag = [False]  # Using a mutable list for shared access

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
    
def fetch_live_price(symbol):
    try:
        ltp_data = smartApi.ltpData("NSE", symbol)
        return float(ltp_data['data']['ltp'])
    except Exception as e:
        logger.error(f"Error fetching live price for {symbol}: {e}")
        return None

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

# API to stop auto-trading (1st definition)
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


@app.route('/api/manual_trade', methods=['POST'])
def manual_trade():
    data = request.get_json()
    symbol = data.get('symbol')
    target_price = float(data.get('target_price', 0))  # default 0 if not provided
    quantity = int(data.get('quantity', 1))
    transaction_type = data.get('transaction_type', 'BUY')
    try:
        order_id = place_order({
            "tradingsymbol": symbol,
            "price": target_price,
            "quantity": quantity,
            "transactiontype": transaction_type,
            "exchange": "NFO",  # or 'NSE' if you want equity
            "producttype": "INTRADAY",
            "ordertype": "LIMIT"
        })
        if order_id:
            return jsonify({"success": True, "message": f"Order placed successfully. ID: {order_id}"})
        else:
            return jsonify({"success": False, "message": "Order placement failed."})
    except Exception as e:
        return jsonify({"success": False, "message": f"Error: {str(e)}"})


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

                if condition == "Condition 1":
                    if basis == "fixed" and live_price >= threshold_value:
                        place_order({"symbol": symbol, "price": live_price, "quantity": quantity})
                        break
                    elif basis == "points" and live_price >= live_price + threshold_value:
                        place_order({"symbol": symbol, "price": live_price, "quantity": quantity})
                        break
                    elif basis == "percentage" and live_price >= live_price * (1 + threshold_value / 100):
                        place_order({"symbol": symbol, "price": live_price, "quantity": quantity})
                        break
                elif condition == "Condition 2":
                    if basis == "fixed" and live_price > threshold_value:
                        place_order({"symbol": symbol, "price": live_price, "quantity": quantity})
                        break
                    elif basis == "points" and live_price > reference_price + threshold_value:
                        place_order({"symbol": symbol, "price": live_price, "quantity": quantity})
                        break
                    elif basis == "percentage" and live_price > reference_price * (1 + threshold_value / 100):
                        place_order({"symbol": symbol, "price": live_price, "quantity": quantity})
                        break

                time.sleep(5)
        except Exception as e:
            logger.error(f"Error in auto-trading: {e}")

    Thread(target=monitor_and_trade).start()
    return jsonify({"success": True, "message": "Auto trading started successfully."})

# API to stop auto-trading (2nd definition, kept as is - duplicate route name)
@app.route('/api/stop_auto_trade', methods=['POST'])
def stop_auto_trade_2():
    # The second definition of the same route, intentionally preserved
    stop_auto_trade_flag[0] = True
    return jsonify({"success": True, "message": "Auto trading stopped successfully."})


# -------------------------------------------------------------------------
# NEW FEATURES IMPLEMENTATION
# (Auto Trailing SL, Auto Trailing Buy, Single-Click Execute, Two-Way Switch,
#  SL Based on Price/Points/%, Automatic Calculation of Loss %)
# -------------------------------------------------------------------------

##############################
# 1) AUTO TRAILING STOP LOSS #
##############################
@app.route('/api/auto_trailing_stop_loss', methods=['POST'])
def auto_trailing_stop_loss():
    """
    Automatically adjusts the stop-loss level as the market moves favorably.
    Example usage:
    JSON Body: {
       "symbol": "NIFTY",
       "quantity": 75,
       "initial_sl": 100,           # e.g. a price or offset
       "trailing_basis": "points",  # 'price', 'points', or 'percentage'
       "trail_value": 20,
       "entry_price": 150
    }
    """
    data = request.get_json()
    symbol = data.get('symbol')
    quantity = int(data.get('quantity', 1))
    initial_sl = float(data.get('initial_sl', 0))
    trailing_basis = data.get('trailing_basis', 'points')  # price, points, percentage
    trail_value = float(data.get('trail_value', 0))
    entry_price = float(data.get('entry_price', 0))

    # We can store the highest price since entry; if the price goes up, move SL up.
    highest_price = [entry_price]  # list so it can be mutated in local function
    is_active = True

    def trailing_sl_thread():
        try:
            while is_active:
                current_price = fetch_live_price(symbol)
                if current_price is None:
                    time.sleep(5)
                    continue

                # Update highest price if current price is new high
                if current_price > highest_price[0]:
                    highest_price[0] = current_price

                # Calculate new Stop Loss if needed
                if trailing_basis == 'price':
                    # If highest price is above some threshold, set SL to that threshold
                    # This is a simplistic approach
                    new_sl = highest_price[0] - trail_value
                elif trailing_basis == 'points':
                    # e.g. if we want to trail by 20 points from the highest price
                    new_sl = highest_price[0] - trail_value
                else:  # 'percentage'
                    new_sl = highest_price[0] * (1 - trail_value / 100.0)

                # If new SL is bigger than the old SL, update it
                if new_sl > initial_sl:
                    initial_sl_local = new_sl
                else:
                    initial_sl_local = initial_sl

                # If the current price breaks below our SL, exit
                if current_price <= initial_sl_local:
                    logger.info(f"Trailing SL triggered at {current_price}. Exiting position.")
                    place_order({
                        "tradingsymbol": symbol,
                        "price": current_price,
                        "quantity": quantity,
                        "transactiontype": "SELL",
                        "exchange": "NFO",
                        "producttype": "INTRADAY",
                        "ordertype": "MARKET"
                    })
                    break

                time.sleep(5)
        except Exception as e:
            logger.error(f"Error in auto trailing stop loss: {e}")

    Thread(target=trailing_sl_thread).start()
    return jsonify({"success": True, "message": "Auto Trailing Stop Loss initiated."})


############################
# 2) AUTO TRAILING BUY     #
############################
@app.route('/api/auto_trailing_buy', methods=['POST'])
def auto_trailing_buy():
    """
    Automatically places a buy order as the market moves favorably.
    Example usage:
    JSON Body: {
       "symbol": "NIFTY",
       "quantity": 75,
       "trailing_basis": "points",  # price, points, or percentage
       "trigger_value": 20,
       "current_reference": 150
    }
    """
    data = request.get_json()
    symbol = data.get('symbol')
    quantity = int(data.get('quantity', 1))
    trailing_basis = data.get('trailing_basis', 'points')
    trigger_value = float(data.get('trigger_value', 0))
    current_reference = float(data.get('current_reference', 0))
    is_active = True

    def trailing_buy_thread():
        try:
            initial_ref_price = current_reference
            while is_active:
                live_price = fetch_live_price(symbol)
                if live_price is None:
                    time.sleep(5)
                    continue

                # Decide if we should buy
                if trailing_basis == 'price':
                    # If current price <= some specified price
                    if live_price <= trigger_value:
                        logger.info(f"Auto trailing BUY triggered at {live_price}. Placing order.")
                        place_order({
                            "tradingsymbol": symbol,
                            "price": live_price,
                            "quantity": quantity,
                            "transactiontype": "BUY",
                            "exchange": "NFO",
                            "producttype": "INTRADAY",
                            "ordertype": "MARKET"
                        })
                        break
                elif trailing_basis == 'points':
                    # If price has moved down certain points from initial_ref_price
                    if live_price <= (initial_ref_price - trigger_value):
                        logger.info(f"Auto trailing BUY triggered. Price fell {trigger_value} from {initial_ref_price}.")
                        place_order({
                            "tradingsymbol": symbol,
                            "price": live_price,
                            "quantity": quantity,
                            "transactiontype": "BUY",
                            "exchange": "NFO",
                            "producttype": "INTRADAY",
                            "ordertype": "MARKET"
                        })
                        break
                else:  # 'percentage'
                    if live_price <= initial_ref_price * (1 - trigger_value / 100.0):
                        logger.info(f"Auto trailing BUY triggered. Price fell {trigger_value}% from {initial_ref_price}.")
                        place_order({
                            "tradingsymbol": symbol,
                            "price": live_price,
                            "quantity": quantity,
                            "transactiontype": "BUY",
                            "exchange": "NFO",
                            "producttype": "INTRADAY",
                            "ordertype": "MARKET"
                        })
                        break

                time.sleep(5)
        except Exception as e:
            logger.error(f"Error in auto trailing buy: {e}")

    Thread(target=trailing_buy_thread).start()
    return jsonify({"success": True, "message": "Auto Trailing Buy initiated."})


##############################################
# 3) SINGLE-CLICK EXECUTE WITHOUT CONDITIONS #
##############################################
@app.route('/api/single_click_execute', methods=['POST'])
def single_click_execute():
    """
    Immediately executes a trade with minimal inputs, no conditions.
    JSON body example:
    {
        "symbol": "NIFTY",
        "quantity": 75,
        "transactiontype": "BUY"
    }
    """
    data = request.get_json()
    symbol = data.get('symbol')
    quantity = int(data.get('quantity', 1))
    transactiontype = data.get('transactiontype', 'BUY')

    try:
        current_price = fetch_live_price(symbol)
        if current_price is None:
            return jsonify({"success": False, "message": "Couldn't fetch live price."})

        order_id = place_order({
            "tradingsymbol": symbol,
            "price": current_price,
            "quantity": quantity,
            "transactiontype": transactiontype,
            "exchange": "NFO",
            "producttype": "INTRADAY",
            "ordertype": "MARKET"
        })
        if order_id:
            return jsonify({"success": True, "message": f"Single-click trade placed. ID: {order_id}"})
        else:
            return jsonify({"success": False, "message": "Order placement failed."})
    except Exception as e:
        logger.error(f"Error in single-click execution: {e}")
        return jsonify({"success": False, "message": str(e)})


################################################
# 4) TWO-WAY CALL AND PUT ORDER SWITCHING LOGIC #
################################################
@app.route('/api/two_way_switch', methods=['POST'])
def two_way_switch():
    """
    Automatically switch between a Call and a Put position (closing the opposite).
    JSON example:
    {
        "current_position": "CALL",    # or "PUT"
        "symbol_call": "NIFTYCALL",
        "symbol_put": "NIFTYPUT",
        "quantity": 75,
        "switch_to": "PUT"            # or "CALL"
    }
    """
    data = request.get_json()
    current_position = data.get('current_position')
    symbol_call = data.get('symbol_call')
    symbol_put = data.get('symbol_put')
    quantity = int(data.get('quantity', 1))
    switch_to = data.get('switch_to')

    try:
        # Close the current position
        if current_position == "CALL":
            # Close the CALL
            place_order({
                "tradingsymbol": symbol_call,
                "transactiontype": "SELL",
                "exchange": "NFO",
                "ordertype": "MARKET",
                "producttype": "INTRADAY",
                "quantity": quantity,
                "price": 0  # Market
            })
            logger.info(f"Closed CALL: {symbol_call}")
        else:
            # Close the PUT
            place_order({
                "tradingsymbol": symbol_put,
                "transactiontype": "SELL",
                "exchange": "NFO",
                "ordertype": "MARKET",
                "producttype": "INTRADAY",
                "quantity": quantity,
                "price": 0
            })
            logger.info(f"Closed PUT: {symbol_put}")

        # Open the new position
        if switch_to == "CALL":
            place_order({
                "tradingsymbol": symbol_call,
                "transactiontype": "BUY",
                "exchange": "NFO",
                "ordertype": "MARKET",
                "producttype": "INTRADAY",
                "quantity": quantity,
                "price": 0
            })
            logger.info(f"Switched to CALL: {symbol_call}")
        else:
            place_order({
                "tradingsymbol": symbol_put,
                "transactiontype": "BUY",
                "exchange": "NFO",
                "ordertype": "MARKET",
                "producttype": "INTRADAY",
                "quantity": quantity,
                "price": 0
            })
            logger.info(f"Switched to PUT: {symbol_put}")

        return jsonify({"success": True, "message": f"Switched from {current_position} to {switch_to} successfully."})
    except Exception as e:
        logger.error(f"Error in two-way switch: {e}")
        return jsonify({"success": False, "message": str(e)})


############################################################
# 5) STOP LOSS BASED ON PRICE, POINTS, AND PERCENTAGE LOGIC #
############################################################
@app.route('/api/stop_loss_variants', methods=['POST'])
def stop_loss_variants():
    """
    Use different ways to define SL:
      - fixed price
      - points offset from entry
      - percentage offset from entry
    JSON example:
    {
        "symbol": "NIFTY",
        "quantity": 75,
        "entry_price": 150,
        "stop_loss_type": "points",  # "price", "points", "percentage"
        "stop_loss_value": 10
    }
    """
    data = request.get_json()
    symbol = data.get("symbol")
    quantity = int(data.get("quantity", 1))
    entry_price = float(data.get("entry_price", 0))
    stop_loss_type = data.get("stop_loss_type", "price")
    stop_loss_value = float(data.get("stop_loss_value", 0))

    # Calculate actual stop loss price
    if stop_loss_type == "price":
        sl_price = stop_loss_value
    elif stop_loss_type == "points":
        sl_price = entry_price - stop_loss_value
    else:
        sl_price = entry_price * (1 - stop_loss_value / 100.0)

    # Start a background thread to watch the price
    is_active = True
    def sl_monitor():
        try:
            while is_active:
                live_price = fetch_live_price(symbol)
                if live_price is None:
                    time.sleep(5)
                    continue
                if live_price <= sl_price:
                    logger.info(f"Stop-loss triggered at {live_price}. SELL order placed.")
                    place_order({
                        "tradingsymbol": symbol,
                        "price": live_price,
                        "quantity": quantity,
                        "transactiontype": "SELL",
                        "exchange": "NFO",
                        "producttype": "INTRADAY",
                        "ordertype": "MARKET"
                    })
                    break
                time.sleep(5)
        except Exception as e:
            logger.error(f"Error in stop_loss_variants: {e}")

    Thread(target=sl_monitor).start()
    return jsonify({
        "success": True, 
        "message": f"Stop loss set at {sl_price} for {symbol} with entry {entry_price}"
    })


####################################################
# 6) AUTOMATIC CALCULATION OF SL LOSS PERCENTAGE    #
####################################################
@app.route('/api/calculate_sl_loss_percentage', methods=['POST'])
def calculate_sl_loss_percentage():
    """
    Given an entry price and a stop loss price, return the potential loss %.
    JSON example:
    {
        "entry_price": 100,
        "stop_loss_price": 95
    }
    """
    data = request.get_json()
    entry_price = float(data.get("entry_price", 0))
    stop_loss_price = float(data.get("stop_loss_price", 0))

    if entry_price <= 0:
        return jsonify({"success": False, "message": "Invalid entry price."})

    loss_amount = entry_price - stop_loss_price
    loss_percentage = (loss_amount / entry_price) * 100.0

    return jsonify({
        "success": True,
        "entry_price": entry_price,
        "stop_loss_price": stop_loss_price,
        "loss_percentage": round(loss_percentage, 2)
    })


# -------------------------------------------------------------------------
# RUN FLASK (Development Only)
# -------------------------------------------------------------------------
if __name__ == "__main__":
    # Just ensure you have a valid 'authToken' if needed for certain calls
    app.run(debug=True)
