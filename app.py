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
    Serves a combined HTML/JS from below for demonstration.
    You can split into templates if you prefer.
    """
    return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Angel One Trading Dashboard (Trailing Stop-Loss Demo)</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha3/dist/css/bootstrap.min.css" rel="stylesheet">
    <script type="text/javascript" src="https://s3.tradingview.com/tv.js"></script>
    <style>
        body {
            background: radial-gradient(circle, #ffffff 30%, #f9f9f9 100%);
            margin: 0; padding: 0;
        }
        .navbar {
            background: linear-gradient(to bottom, #ffffff, #f0f0f0);
            padding: 20px 30px;
            box-shadow: 0 4px 10px rgba(255, 253, 255, 0.4);
            border-bottom: 2px solid #007bff;
        }
        .navbar-brand {
            font-size: 2rem;
            font-weight: bold;
            color: #007bff;
        }
        .container-buttons button {
            margin: 5px;
            border: none;
            padding: 6px 12px;
            border-radius: 4px;
            cursor: pointer;
            font-weight: bold;
            color: #fff;
            background: linear-gradient(90deg, #228B22, #FF0000);
            animation: gradient-flow 4s infinite, button-glow 2s infinite alternate;
            background-size: 200% 200%;
        }
        @keyframes gradient-flow {
            0% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
            100% { background-position: 0% 50%; }
        }
        @keyframes button-glow {
            0% { box-shadow: 0 0 10px rgba(34, 139, 34, 0.7); }
            100% { box-shadow: 0 0 20px rgba(255, 0, 0, 0.8); }
        }
        .response-box {
            display: none;
            margin-top: 10px;
            padding: 10px;
            border-radius: 5px;
        }
        #chart-container {
            width: 100%; height: 700px;
            border: 1px solid #008000;
            border-radius: 10px;
            box-shadow: 0 0 15px rgba(255, 215, 0, 0.5);
            background-color: #ffffff;
            margin-top: 20px;
        }
        footer {
            background: #fff;
            color: #000;
            padding: 20px;
            text-align: center;
            border-top: 2px solid #FF2C2C;
        }
    </style>
</head>
<body>
<nav class="navbar">
    <span class="navbar-brand">Angel One Trading Dashboard</span>
</nav>

<div class="container mt-3">
    <div class="container-buttons d-flex flex-wrap">
        <button onclick="showSection('loginSection')">Login</button>
        <button onclick="showSection('manualTradeSection')">Manual Trade</button>
        <button onclick="showSection('placeOrderSection')">Place Order (Demo)</button>
        <button onclick="showSection('gttSection')">Create GTT</button>
        <button onclick="showSection('listGttSection')">List GTT</button>
        <button onclick="showSection('profileSection')">Profile</button>
        <button onclick="showSection('autoTradeSection')">Auto Trade (Buy)</button>
        <button onclick="showSection('autoStopLossSection')">Auto Stop-Loss Sell</button>
    </div>
</div>

<div class="container-fluid">
    <div class="row">
        <!-- LEFT SIDE SECTIONS -->
        <div class="col-md-6">

            <!-- LOGIN -->
            <div id="loginSection" style="display:none; padding: 10px;">
                <h4>Login</h4>
                <div class="mb-3">
                    <label>Username:</label>
                    <input type="text" id="username" class="form-control">
                </div>
                <div class="mb-3">
                    <label>Password:</label>
                    <input type="password" id="password" class="form-control">
                </div>
                <div class="mb-3">
                    <label>TOTP Secret:</label>
                    <input type="text" id="totp" class="form-control">
                </div>
                <button class="btn btn-primary" onclick="login()">Login</button>
                <div id="login-response" class="response-box"></div>
            </div>

            <!-- MANUAL TRADE -->
            <div id="manualTradeSection" style="display:none; padding: 10px;">
                <h4>Manual Trade</h4>
                <div class="mb-3">
                    <label>Symbol:</label>
                    <input type="text" id="manual-symbol" class="form-control" placeholder="e.g. SBIN">
                </div>
                <div class="mb-3">
                    <label>Quantity:</label>
                    <input type="number" id="manual-quantity" class="form-control" value="1">
                </div>
                <div class="mb-3">
                    <label>Transaction Type:</label>
                    <select id="manual-transaction" class="form-select">
                        <option value="BUY">Buy</option>
                        <option value="SELL">Sell</option>
                    </select>
                </div>
                <button class="btn btn-success" onclick="performManualTrade()">Execute Manual Trade</button>
                <div id="manual-trade-response" class="response-box"></div>
            </div>

            <!-- PLACE ORDER DEMO -->
            <div id="placeOrderSection" style="display:none; padding: 10px;">
                <h4>Place Order (Demo)</h4>
                <div class="mb-2">
                    <label>Variety:</label>
                    <select id="order-variety" class="form-select">
                        <option value="NORMAL">NORMAL</option>
                        <option value="STOPLOSS">STOPLOSS</option>
                        <option value="AMO">AMO</option>
                        <option value="ROBO">ROBO</option>
                    </select>
                </div>
                <div class="mb-2">
                    <label>Trading Symbol:</label>
                    <input type="text" id="order-tradingsymbol" class="form-control" value="SBIN-EQ">
                </div>
                <div class="mb-2">
                    <label>Symbol Token:</label>
                    <input type="text" id="order-symboltoken" class="form-control" value="3045">
                </div>
                <div class="mb-2">
                    <label>Transaction Type:</label>
                    <select id="order-transactiontype" class="form-select">
                        <option value="BUY">BUY</option>
                        <option value="SELL">SELL</option>
                    </select>
                </div>
                <div class="mb-2">
                    <label>Exchange:</label>
                    <select id="order-exchange" class="form-select">
                        <option value="NSE">NSE</option>
                        <option value="BSE">BSE</option>
                        <option value="NFO">NFO</option>
                    </select>
                </div>
                <div class="mb-2">
                    <label>Order Type:</label>
                    <select id="order-ordertype" class="form-select">
                        <option value="MARKET">MARKET</option>
                        <option value="LIMIT">LIMIT</option>
                        <option value="STOPLOSS_LIMIT">STOPLOSS_LIMIT</option>
                        <option value="STOPLOSS_MARKET">STOPLOSS_MARKET</option>
                    </select>
                </div>
                <div class="mb-2">
                    <label>Product Type:</label>
                    <select id="order-producttype" class="form-select">
                        <option value="DELIVERY">DELIVERY</option>
                        <option value="CARRYFORWARD">CARRYFORWARD</option>
                        <option value="MARGIN">MARGIN</option>
                        <option value="INTRADAY">INTRADAY</option>
                    </select>
                </div>
                <div class="mb-2">
                    <label>Duration:</label>
                    <select id="order-duration" class="form-select">
                        <option value="DAY">DAY</option>
                        <option value="IOC">IOC</option>
                    </select>
                </div>
                <div class="mb-2">
                    <label>Price:</label>
                    <input type="text" id="order-price" class="form-control" value="19500">
                </div>
                <div class="mb-2">
                    <label>Quantity:</label>
                    <input type="text" id="order-quantity" class="form-control" value="1">
                </div>
                <button class="btn btn-success" onclick="placeOrder()">Place Order</button>
                <div id="order-response" class="response-box"></div>
            </div>

            <!-- CREATE GTT -->
            <div id="gttSection" style="display:none; padding: 10px;">
                <h4>Create GTT Rule</h4>
                <div class="mb-2">
                    <label>Trading Symbol:</label>
                    <input type="text" id="gtt-tradingsymbol" class="form-control" value="SBIN-EQ">
                </div>
                <div class="mb-2">
                    <label>Symbol Token:</label>
                    <input type="text" id="gtt-symboltoken" class="form-control" value="3045">
                </div>
                <div class="mb-2">
                    <label>Exchange:</label>
                    <input type="text" id="gtt-exchange" class="form-control" value="NSE">
                </div>
                <div class="mb-2">
                    <label>Product Type:</label>
                    <input type="text" id="gtt-producttype" class="form-control" value="MARGIN">
                </div>
                <div class="mb-2">
                    <label>Transaction Type:</label>
                    <input type="text" id="gtt-transactiontype" class="form-control" value="BUY">
                </div>
                <div class="mb-2">
                    <label>Price:</label>
                    <input type="number" id="gtt-price" class="form-control" value="100000">
                </div>
                <div class="mb-2">
                    <label>Qty:</label>
                    <input type="number" id="gtt-qty" class="form-control" value="10">
                </div>
                <div class="mb-2">
                    <label>Disclosed Qty:</label>
                    <input type="number" id="gtt-disclosedqty" class="form-control" value="10">
                </div>
                <div class="mb-2">
                    <label>Trigger Price:</label>
                    <input type="number" id="gtt-triggerprice" class="form-control" value="200000">
                </div>
                <div class="mb-2">
                    <label>Time Period:</label>
                    <input type="number" id="gtt-timeperiod" class="form-control" value="365">
                </div>
                <button class="btn btn-warning" onclick="createGttRule()">Create GTT</button>
                <div id="gtt-create-response" class="response-box"></div>
            </div>

            <!-- LIST GTT -->
            <div id="listGttSection" style="display:none; padding: 10px;">
                <h4>List GTT Rules</h4>
                <button class="btn btn-info" onclick="listGttRules()">List GTT</button>
                <div id="gtt-list-response" class="response-box"></div>
            </div>

            <!-- PROFILE -->
            <div id="profileSection" style="display:none; padding: 10px;">
                <h4>Profile</h4>
                <button class="btn btn-info" onclick="fetchProfile()">Fetch Profile</button>
                <div id="profile-response" class="response-box" style="overflow-x:auto;"></div>
            </div>

            <!-- AUTO TRADE (BUY) -->
            <div id="autoTradeSection" style="display:none; padding: 10px;">
                <h4>Auto Trade (Buy Condition)</h4>
                <p>Example logic: auto trade once price crosses a threshold. Simplified here.</p>
                <div class="mb-2">
                    <label>Symbol:</label>
                    <input type="text" id="auto-symbol" class="form-control" placeholder="e.g. SBIN">
                </div>
                <div class="mb-2">
                    <label>Quantity:</label>
                    <input type="number" id="auto-quantity" class="form-control" value="1">
                </div>
                <div class="mb-2">
                    <label>Condition:</label>
                    <select id="auto-condition" class="form-select">
                        <option value="Condition 1">Condition 1</option>
                        <option value="Condition 2">Condition 2</option>
                    </select>
                </div>
                <div class="mb-2">
                    <label>Basis:</label>
                    <select id="auto-basis" class="form-select">
                        <option value="fixed">Fixed Price</option>
                        <option value="points">Points</option>
                        <option value="percentage">Percentage</option>
                    </select>
                </div>
                <div class="mb-2">
                    <label>Threshold Value:</label>
                    <input type="number" id="auto-threshold" class="form-control" value="100">
                </div>
                <div class="mb-2">
                    <label>Reference Price (optional):</label>
                    <input type="number" id="auto-reference" class="form-control" value="0">
                </div>
                <button class="btn btn-success" onclick="startAutoTrade()">Start Auto Trade</button>
                <button class="btn btn-danger" onclick="stopAutoTrade()">Stop Auto Trade</button>
                <div id="auto-trade-response" class="response-box"></div>
            </div>

            <!-- AUTO STOP-LOSS SELL (Trailing) -->
            <div id="autoStopLossSection" style="display:none; padding:10px;">
                <h4>Auto Stop-Loss Sell (Trailing)</h4>
                <p>
                  Two scenarios:
                  <br>1) Price never rises => Sell if price hits buyPrice*0.95
                  <br>2) Price rises => Trailing stop: track highest, sell if price hits highest*0.95
                </p>
                <div class="mb-2">
                    <label>Symbol (already bought):</label>
                    <input type="text" id="stoploss-symbol" class="form-control" placeholder="e.g. SBIN">
                </div>
                <div class="mb-2">
                    <label>Buy Price:</label>
                    <input type="number" id="stoploss-buyprice" class="form-control" placeholder="The price at which you bought">
                </div>
                <div class="mb-2">
                    <label>Quantity:</label>
                    <input type="number" id="stoploss-quantity" class="form-control" value="1">
                </div>
                <div class="mb-2">
                    <label>Scenario:</label>
                    <select id="stoploss-scenario" class="form-select">
                        <option value="1">Scenario 1 (No Price Rise)</option>
                        <option value="2">Scenario 2 (Trailing if Price Rises)</option>
                    </select>
                </div>
                <button class="btn btn-warning" onclick="startTrailingStop()">Start Auto Stop-Loss Sell</button>
                <button class="btn btn-danger" onclick="stopTrailingStop()">Stop Auto Stop-Loss Sell</button>
                <div id="stoploss-response" class="response-box"></div>
            </div>

        </div>
        <!-- RIGHT SIDE CHART -->
        <div class="col-md-6">
            <div id="chart-container"></div>
        </div>
    </div>
</div>

<footer>
    <p>Angel One Trading Dashboard &mdash; Trailing Stop-Loss Demo</p>
</footer>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
<script>
    // ========== GLOBALS ==========
    let g_authToken = null;
    let g_refreshToken = null;
    let chartWidget = null;

    // ========== SECTION NAVIGATION ==========
    function showSection(sectionId) {
        const allSections = [
            'loginSection','manualTradeSection','placeOrderSection',
            'gttSection','listGttSection','profileSection',
            'autoTradeSection','autoStopLossSection'
        ];
        allSections.forEach(s => document.getElementById(s).style.display = 'none');
        document.getElementById(sectionId).style.display = 'block';
        document.getElementById(sectionId).scrollIntoView({ behavior: 'smooth' });
    }

    // ========== LOGIN ==========
    function login() {
        const username = document.getElementById("username").value;
        const password = document.getElementById("password").value;
        const totp = document.getElementById("totp").value;

        fetch('/api/login', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ username, password, totp })
        })
        .then(res => res.json())
        .then(data => {
            const resp = document.getElementById("login-response");
            resp.style.display = 'block';
            if (data.success) {
                resp.textContent = "Login successful!";
                resp.style.color = "green";
                g_authToken = data.authToken;
                g_refreshToken = data.refreshToken;
            } else {
                resp.textContent = data.message || "Login failed!";
                resp.style.color = "red";
            }
        })
        .catch(err => {
            const resp = document.getElementById("login-response");
            resp.style.display = 'block';
            resp.textContent = "Error: " + err;
            resp.style.color = "red";
        });
    }

    // ========== MANUAL TRADE ==========
    function performManualTrade() {
        const symbol = document.getElementById("manual-symbol").value.trim();
        const quantity = +document.getElementById("manual-quantity").value;
        const transaction_type = document.getElementById("manual-transaction").value;

        // Update chart
        if (symbol) {
            updateLiveChart(symbol);
        }

        fetch('/api/manual_trade', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                symbol,
                target_price: 0,  // or user input if needed
                quantity,
                transaction_type,
                authToken: g_authToken,
                refreshToken: g_refreshToken
            })
        })
        .then(res => res.json())
        .then(data => {
            const resp = document.getElementById("manual-trade-response");
            resp.style.display = 'block';
            if (data.success) {
                resp.textContent = data.message || "Manual trade placed successfully!";
                resp.style.color = "green";
            } else {
                resp.textContent = data.message || "Manual trade failed.";
                resp.style.color = "red";
            }
        })
        .catch(err => {
            const resp = document.getElementById("manual-trade-response");
            resp.style.display = 'block';
            resp.textContent = "Error: " + err;
            resp.style.color = "red";
        });
    }

    // ========== PLACE ORDER DEMO ==========
    function placeOrder() {
        const orderParams = {
            variety: document.getElementById("order-variety").value,
            tradingsymbol: document.getElementById("order-tradingsymbol").value,
            symboltoken: document.getElementById("order-symboltoken").value,
            transactiontype: document.getElementById("order-transactiontype").value,
            exchange: document.getElementById("order-exchange").value,
            ordertype: document.getElementById("order-ordertype").value,
            producttype: document.getElementById("order-producttype").value,
            duration: document.getElementById("order-duration").value,
            price: document.getElementById("order-price").value,
            squareoff: "0",
            stoploss: "0",
            quantity: document.getElementById("order-quantity").value
        };

        // Update chart if the symbol changes
        if (orderParams.tradingsymbol) {
            updateLiveChart(orderParams.tradingsymbol);
        }

        fetch('/api/place_order', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ orderParams })
        })
        .then(res => res.json())
        .then(data => {
            const resp = document.getElementById("order-response");
            resp.style.display = 'block';
            if (data.success) {
                resp.textContent = "Order placed: " + data.orderid;
                resp.style.color = "green";
            } else {
                resp.textContent = "Order failed: " + JSON.stringify(data);
                resp.style.color = "red";
            }
        })
        .catch(err => {
            const resp = document.getElementById("order-response");
            resp.style.display = 'block';
            resp.textContent = "Error: " + err;
            resp.style.color = "red";
        });
    }

    // ========== CREATE GTT ==========
    function createGttRule() {
        const gttParams = {
            tradingsymbol: document.getElementById("gtt-tradingsymbol").value,
            symboltoken: document.getElementById("gtt-symboltoken").value,
            exchange: document.getElementById("gtt-exchange").value,
            producttype: document.getElementById("gtt-producttype").value,
            transactiontype: document.getElementById("gtt-transactiontype").value,
            price: parseFloat(document.getElementById("gtt-price").value),
            qty: parseInt(document.getElementById("gtt-qty").value),
            disclosedqty: parseInt(document.getElementById("gtt-disclosedqty").value),
            triggerprice: parseFloat(document.getElementById("gtt-triggerprice").value),
            timeperiod: parseInt(document.getElementById("gtt-timeperiod").value)
        };

        fetch('/api/create_gtt_rule', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ gttParams })
        })
        .then(res => res.json())
        .then(data => {
            const resp = document.getElementById("gtt-create-response");
            resp.style.display = 'block';
            if (data.success) {
                resp.textContent = "GTT created: " + data.rule_id;
                resp.style.color = "green";
            } else {
                resp.textContent = "Failed: " + JSON.stringify(data);
                resp.style.color = "red";
            }
        })
        .catch(err => {
            const resp = document.getElementById("gtt-create-response");
            resp.style.display = 'block';
            resp.textContent = "Error: " + err;
            resp.style.color = "red";
        });
    }

    // ========== LIST GTT ==========
    function listGttRules() {
        fetch('/api/list_gtt_rules', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({})
        })
        .then(res => res.json())
        .then(data => {
            const resp = document.getElementById("gtt-list-response");
            resp.style.display = 'block';
            if (data.success) {
                resp.textContent = "GTT list:\n" + JSON.stringify(data.gtt_list, null, 2);
                resp.style.color = "green";
            } else {
                resp.textContent = "List GTT failed: " + JSON.stringify(data);
                resp.style.color = "red";
            }
        })
        .catch(err => {
            const resp = document.getElementById("gtt-list-response");
            resp.style.display = 'block';
            resp.textContent = "Error: " + err;
            resp.style.color = "red";
        });
    }

    // ========== PROFILE ==========
    function fetchProfile() {
        if (!g_refreshToken) {
            alert("You must log in first!");
            return;
        }
        fetch('/api/get_profile', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ refreshToken: g_refreshToken })
        })
        .then(res => res.json())
        .then(data => {
            const resp = document.getElementById("profile-response");
            resp.style.display = 'block';
            if (data.success) {
                resp.innerHTML = JSON.stringify(data.profile, null, 2);
                resp.style.color = "green";
            } else {
                resp.textContent = "Profile fetch failed: " + data.error;
                resp.style.color = "red";
            }
        })
        .catch(err => {
            const resp = document.getElementById("profile-response");
            resp.style.display = 'block';
            resp.textContent = "Error: " + err;
            resp.style.color = "red";
        });
    }

    // ========== AUTO TRADE (BUY) ==========
    function startAutoTrade() {
        const symbol = document.getElementById("auto-symbol").value.trim();
        const quantity = +document.getElementById("auto-quantity").value;
        const condition = document.getElementById("auto-condition").value;
        const basis = document.getElementById("auto-basis").value;
        const threshold_value = +document.getElementById("auto-threshold").value;
        const reference_price = +document.getElementById("auto-reference").value;

        if (symbol) {
            updateLiveChart(symbol);
        }

        fetch('/api/auto_trade', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                symbol, quantity, condition, basis,
                threshold_value, reference_price
            })
        })
        .then(res => res.json())
        .then(data => {
            const resp = document.getElementById("auto-trade-response");
            resp.style.display = 'block';
            if (data.success) {
                resp.textContent = data.message;
                resp.style.color = "green";
            } else {
                resp.textContent = data.message || "Auto trade failed.";
                resp.style.color = "red";
            }
        })
        .catch(err => {
            const resp = document.getElementById("auto-trade-response");
            resp.style.display = 'block';
            resp.textContent = "Error: " + err;
            resp.style.color = "red";
        });
    }

    function stopAutoTrade() {
        fetch('/api/stop_auto_trade', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({})
        })
        .then(res => res.json())
        .then(data => {
            const resp = document.getElementById("auto-trade-response");
            resp.style.display = 'block';
            if (data.success) {
                resp.textContent = data.message;
                resp.style.color = "green";
            } else {
                resp.textContent = data.message || "Stop failed.";
                resp.style.color = "red";
            }
        })
        .catch(err => {
            const resp = document.getElementById("auto-trade-response");
            resp.style.display = 'block';
            resp.textContent = "Error: " + err;
            resp.style.color = "red";
        });
    }

    // ========== AUTO STOP-LOSS SELL (TRAILING) ==========
    function startTrailingStop() {
        const symbol = document.getElementById("stoploss-symbol").value.trim();
        const buy_price = parseFloat(document.getElementById("stoploss-buyprice").value);
        const quantity = parseInt(document.getElementById("stoploss-quantity").value);
        const scenario = document.getElementById("stoploss-scenario").value; // "1" or "2"

        if (!symbol || !buy_price || !quantity) {
            alert("Please fill symbol, buy price, and quantity.");
            return;
        }
        updateLiveChart(symbol);

        fetch('/api/auto_stoploss_sell', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                symbol, buy_price, quantity, scenario
            })
        })
        .then(res => res.json())
        .then(data => {
            const resp = document.getElementById("stoploss-response");
            resp.style.display = 'block';
            if (data.success) {
                resp.textContent = data.message;
                resp.style.color = "green";
            } else {
                resp.textContent = data.error || "Failed to start trailing stop-loss.";
                resp.style.color = "red";
            }
        })
        .catch(err => {
            const resp = document.getElementById("stoploss-response");
            resp.style.display = 'block';
            resp.textContent = "Error: " + err;
            resp.style.color = "red";
        });
    }

    function stopTrailingStop() {
        fetch('/api/stop_auto_stoploss_sell', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({})
        })
        .then(res => res.json())
        .then(data => {
            const resp = document.getElementById("stoploss-response");
            resp.style.display = 'block';
            if (data.success) {
                resp.textContent = data.message;
                resp.style.color = "green";
            } else {
                resp.textContent = data.error || "Failed to stop trailing stop.";
                resp.style.color = "red";
            }
        })
        .catch(err => {
            const resp = document.getElementById("stoploss-response");
            resp.style.display = 'block';
            resp.textContent = "Error: " + err;
            resp.style.color = "red";
        });
    }

    // ========== TRADINGVIEW CHART ==========
    function updateLiveChart(symbolInput) {
        let symbol = symbolInput.toUpperCase().includes(':') ? symbolInput : "NSE:" + symbolInput.toUpperCase();
        if (chartWidget) {
            chartWidget.remove();
        }
        chartWidget = new TradingView.widget({
            symbol: symbol,
            interval: "5",
            timezone: "Asia/Kolkata",
            theme: "dark",
            style: "1",
            locale: "en",
            toolbar_bg: "#f1f3f6",
            container_id: "chart-container",
            width: "100%",
            height: 700
        });
    }

    // Load a default chart
    window.addEventListener('DOMContentLoaded', () => {
        updateLiveChart("NIFTY");
    });
</script>

</body>
</html>
    """

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

# 8. AUTO STOP-LOSS SELL (Trailing)
@app.route('/api/auto_stoploss_sell', methods=['POST'])
def auto_stoploss_sell():
    """
    Scenario 1: Price never goes above buy_price => stop-loss = buy_price * 0.95.
    If price dips <= that, sell.

    Scenario 2: Price moves above buy_price => track highest price seen.
    stop-loss = highest_price * 0.95.
    If price dips <= that, sell.
    """
    data = request.get_json()
    symbol = data.get('symbol')
    buy_price = float(data.get('buy_price'))
    quantity = int(data.get('quantity'))
    scenario = data.get('scenario')

    # reset the global stop-flag
    stop_trailing_stop_flag[0] = False

    def monitor_and_sell():
        try:
            highest_price = buy_price  # track the highest if scenario=2
            # initial stop loss is buy_price * 0.95
            stop_loss = buy_price * 0.95

            while not stop_trailing_stop_flag[0]:
                live_price = fetch_live_price(symbol)
                if live_price is None:
                    time.sleep(5)
                    continue

                # SCENARIO 1 => If price does not rise above buy
                # stop_loss remains at buy_price * 0.95
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

                # SCENARIO 2 => If price rises, we keep track of the new highest and update stop_loss
                elif scenario == "2":
                    if live_price > highest_price:
                        highest_price = live_price
                        stop_loss = highest_price * 0.95
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
