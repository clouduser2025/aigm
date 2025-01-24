# brokers.py

import pyotp
from SmartApi import SmartConnect  # Assuming Angel's API
import requests  # For Shonnay's API
import os

class BrokerInterface:
    def place_order(self, user, symbol, quantity, transaction_type, price):
        raise NotImplementedError("This method should be overridden by subclasses.")

class AngelBroker(BrokerInterface):
    def __init__(self, api_key, client_code, client_password, totp_secret):
        self.api_key = api_key
        self.client_code = client_code
        self.client_password = client_password
        self.totp_secret = totp_secret
        self.obj = self.login()

    def login(self):
        try:
            obj = SmartConnect(api_key=self.api_key)
            data = obj.generateSession(
                self.client_code,
                self.client_password,
                pyotp.TOTP(self.totp_secret).now()
            )
            print("Angel: Successfully logged in.")
            return obj
        except Exception as e:
            print(f"Angel: Error during login: {e}")
            raise e

    def get_rms_limit(self):
        try:
            return self.obj.rmsLimit()
        except Exception as e:
            print(f"Angel: Error fetching RMS limit: {e}")
            return {"status": False, "message": str(e)}

    def get_ltp_data(self, exchange, tradingsymbol, symboltoken):
        try:
            return self.obj.ltpData(exchange, tradingsymbol, symboltoken)
        except Exception as e:
            print(f"Angel: Error fetching LTP data: {e}")
            return {"status": False, "message": str(e)}

    def place_order(self, user, symbol, quantity, transaction_type, price):
        try:
            # Construct the order parameters as per Angel's API
            order_params = {
                "variety": "NORMAL",
                "tradingsymbol": symbol,
                "symboltoken": user.symboltoken,  # Ensure User model has symboltoken
                "transactiontype": transaction_type.upper(),
                "exchange": user.exchange.upper(),
                "ordertype": "LIMIT",
                "producttype": "INTRADAY",
                "duration": "DAY",
                "price": price,
                "quantity": quantity
            }
            order_id = self.obj.placeOrder(order_params)
            print(f"Angel: Order placed successfully. Order ID: {order_id}")
            return order_id
        except Exception as e:
            print(f"Angel: Error placing order: {e}")
            raise e

class ShonnayBroker(BrokerInterface):
    def __init__(self, client_id, client_secret):
        self.client_id = client_id
        self.client_secret = client_secret
        self.token = self.authenticate()

    def authenticate(self):
        # Implement Shonnay's authentication mechanism
        # This is a placeholder implementation
        try:
            response = requests.post(
                "https://api.shonnay.com/auth/token",
                data={
                    "client_id": self.client_id,
                    "client_secret": self.client_secret
                }
            )
            response.raise_for_status()
            token = response.json().get("access_token")
            print("Shonnay: Successfully authenticated.")
            return token
        except Exception as e:
            print(f"Shonnay: Authentication failed: {e}")
            raise e

    def place_order(self, user, symbol, quantity, transaction_type, price):
        try:
            # Construct the order payload as per Shonnay's API
            order_payload = {
                "symbol": symbol,
                "quantity": quantity,
                "transaction_type": transaction_type.upper(),
                "price": price
            }
            headers = {
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json"
            }
            response = requests.post(
                "https://api.shonnay.com/orders",
                json=order_payload,
                headers=headers
            )
            response.raise_for_status()
            order_id = response.json().get("order_id")
            print(f"Shonnay: Order placed successfully. Order ID: {order_id}")
            return order_id
        except Exception as e:
            print(f"Shonnay: Error placing order: {e}")
            raise e
