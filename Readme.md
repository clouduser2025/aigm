conda activate trade

cd C:\Users\shafe\project
python app.py
python live_price.py


pip install lightweight-charts
python -m eventlet app.py



Step 5: Access Pages in Your Browser
Once the application is running, open your browser and visit the following URLs:

Home Page
URL: http://127.0.0.1:5000/
Description: Displays the form for entering exchange, symbol, and token details.
Result Page
After submitting the form on the Home Page, you'll be redirected here.
Chart Page
Accessed via the "View Live Chart" button on the Results Page.
Users Page
URL: http://127.0.0.1:5000/users
Description: Lists all registered users.
Trades Page
URL: http://127.0.0.1:5000/trades
Description: Lists all trades made by users.
Request Registration Form
URL: http://127.0.0.1:5000/request_registration_form
Description: Displays a form for requesting a registration token.