from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, EmailField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
import re

def validate_username(form, field):
    if not re.match("^[a-zA-Z0-9_]{3,20}$", field.data):
        raise ValidationError("Username must be 3-20 characters (letters, numbers, _)")

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), validate_username])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', 
        validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')