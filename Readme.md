conda activate trade

1.	Only one Admin logs in (not the end users).
2.	Admin can:
o	Register multiple trading users (manually or via CSV).
o	Place Manual Orders (Buy/Sell) on behalf of any trading user.
o	Configure Auto Trades (with conditions) for any user.
o	Configure Stop-Loss (fixed or trailing) for any user.
3.	All trades update a real-time chart (Socket.IO + Chart.js).
4.	Default Quantity: Each trading user has a “default quantity.” If you place an order or auto trade with quantity=0, it falls back to that user’s default.
5.	Multiple Brokers: Each user can be “angel” or “shonnay.” We simulate a “live price” from Angel.
6.	A single “Place Order” page with Bootstrap 5 + Font Awesome + Tabbed UI:
o	Manual (Buy/Sell)
o	Auto (conditions)
o	Stop-Loss (fixed or trailing)
o	Explanation
