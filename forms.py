# forms.py

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField, FloatField, SelectField
from wtforms.validators import DataRequired, Length, EqualTo, NumberRange

class RegistrationForm(FlaskForm):
    user_id = StringField('User ID', validators=[DataRequired(), Length(min=2, max=150)])
    broker = SelectField(
        'Broker',
        choices=[('angel', 'Angel'), ('shonnay', 'Shonnay')],
        validators=[DataRequired()]
    )
    api_key = StringField('API Key', validators=[DataRequired(), Length(min=10, max=150)])
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=150)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=150)])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match.')
    ])
    totp_token = StringField('TOTP Token', validators=[Length(min=6, max=6)])  # Only for Angel
    default_quantity = IntegerField('Default Quantity', validators=[DataRequired(), NumberRange(min=1)])
    exchange = StringField('Exchange', validators=[Length(min=2, max=50)])  # Only for Angel
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=150)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=150)])
    submit = SubmitField('Login')

class OrderForm(FlaskForm):
    symbol = StringField('Symbol', validators=[DataRequired(), Length(min=1, max=50)])
    quantity = IntegerField('Quantity', validators=[DataRequired(), NumberRange(min=1)])
    transaction_type = SelectField(
        'Transaction Type',
        choices=[('BUY', 'Buy'), ('SELL', 'Sell')],
        validators=[DataRequired()]
    )
    price = FloatField('Price', validators=[DataRequired(), NumberRange(min=0.0)])
    submit = SubmitField('Place Order')
