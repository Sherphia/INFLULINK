from flask_wtf import FlaskForm
from wtforms import IntegerField, StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import DataRequired, Length, EqualTo

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    role = SelectField('Role', choices=[('admin', 'Admin'), ('sponsor', 'Sponsor'), ('influencer', 'Influencer')], validators=[DataRequired()])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class EditInfluencerProfileForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    category = StringField('Category', validators=[DataRequired()])
    niche = StringField('Niche', validators=[DataRequired()])
    reach = StringField('Reach', validators=[DataRequired()])
    submit = SubmitField('Update Profile')

class InfluencerRegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=80)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    category = StringField('Category', validators=[DataRequired()])
    niche = StringField('Niche', validators=[DataRequired()])
    reach = IntegerField('Reach', validators=[DataRequired()])
    submit = SubmitField('Register')