from flask_wtf import Form
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import Required, Email, Length, Regexp, EqualTo
from wtforms import ValidationError
from ..database.models import User


class LoginForm(Form):

	email = StringField('Email', validators=[Required(), Length(1,64), Email()])
	password = PasswordField('Password', validators=[Required()])
	remember_me = BooleanField('Keep me logged in')
	submit = SubmitField('Log in')

class RegistrationForm(Form):

	email = StringField('Email', validators=[Required(), Length(1,64), Email()])
	username = StringField('Username', validators=[
		Required(), Length(1, 64), Regexp('^[a-zA-Z][a-zA-Z0-9_.]*$', 0,
			'Username must have only letters, numbers, undescore or dots.')])
	password = PasswordField('Password', validators=[
		Required(), EqualTo('password2', message='Password didn\'t match')])
	password2 = PasswordField('Confirm Password', validators=[Required()])
	submit = SubmitField('Register')

	def validate_email(self, field):
		if User.query.filter_by(email=field.data).first():
			raise ValidationError('Email already exists')

	def validate_username(self, field):
		if User.query.filter_by(username=field.data).first():
			raise ValidationError('Username already in uses.')
