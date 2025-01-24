from SmartApi.smartWebSocketOrderUpdate import SmartWebSocketOrderUpdate
from SmartApi import SmartConnect
import pyotp
import threading
import time
from datetime import datetime
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

API_KEY = os.getenv("API_KEY")
CLIENT_CODE = os.getenv("CLIENT_CODE")
CLIENT_PASSWORD = os.getenv("CLIENT_PASSWORD")
TOTP_SECRET = os.getenv("TOTP_SECRET")


def AngelLogin(api_key, username, password, totp_secret):
    obj = SmartConnect(api_key=api_key)
    data = obj.generateSession(username, password, pyotp.TOTP(totp_secret).now())
    print("Logged in successfully!")
    return obj


def check_trading_balance(obj):
    """Fetch and display trading balance."""
    rms_data = obj.rmsLimit()
    if rms_data['status']:
        data = rms_data['data']
        print("Trading Balance Details:")
        print(f"Available Cash: {data.get('availablecash', 'N/A')}")
        print(f"Net: {data.get('net', 'N/A')}")
        print(f"Collateral: {data.get('collateral', 'N/A')}")
        print(f"M2M Unrealized: {data.get('m2munrealized', 'N/A')}")
        print(f"M2M Realized: {data.get('m2mrealized', 'N/A')}")
    else:
        print("Error fetching trading balance:", rms_data.get("message"))


def fetch_live_price(obj, exchange, tradingsymbol, symboltoken):
    """Fetch the latest price of a trading symbol."""
    try:
        ltp_data = obj.ltpData(exchange, tradingsymbol, symboltoken)
        if ltp_data['status']:
            print(f"Live Price for {tradingsymbol}: {ltp_data['data']['ltp']}")
        else:
            print(f"Error fetching live price: {ltp_data.get('message')}")
    except Exception as e:
        print(f"Exception occurred: {e}")


# Login to Angel API
ANGEL_OBJ = AngelLogin(API_KEY, CLIENT_CODE, CLIENT_PASSWORD, TOTP_SECRET)

# Check Trading Balance
check_trading_balance(ANGEL_OBJ)

# User input for trading symbol
print("\nEnter the trading symbol details:")
exchange = input("Exchange (e.g., NSE, BSE): ").strip().upper()
tradingsymbol = input("Trading Symbol (e.g., RELIANCE, INFY): ").strip().upper()
symboltoken = input("Symbol Token (e.g., 2885): ").strip()

# Fetch Live Price for the entered symbol
fetch_live_price(ANGEL_OBJ, exchange, tradingsymbol, symboltoken)
