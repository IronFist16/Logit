from flask import render_template, redirect, url_for, flash, request
from . import auth
from flask_login import login_user, logout_user, login_required, current_user
from .forms import LoginForm, RegistrationForm
from ..database.models import User, Role
from .. import db
from email import send_email

@auth.login_required
def before_request():
	if current_user.is_authenticated and not current_user.confirmed \
		and request.endpoint[:5] != 'auth':
		return redirect(url_for('auth.unconfirmed'))

@auth.route('/login', methods=['GET', 'POST'])
def login():
	form = LoginForm()
	if form.validate_on_submit():
		user = User.query.filter_by(email=form.email.data).first()
		if user is not None and user.verify_password(form.password.data):
			login_user(user, form.remember_me.data)
			return redirect(request.get('next') or url_for('main.index'))
		flash('Invalid username or password.')
	return render_template('auth/login.html')

@auth.route('/logout', methods=['GET', 'POSt'])
def logout():
	logout_user()
	flash('You have been logged out !')
	return redirect(url_for('main.index'))

@auth.route('/register', methods=['GET', 'POST'])
def register():
	form = RegistrationForm()
	if form.validate_on_submit():
		user = User(
			email=form.email.data,
			username=form.username.data,
			password=form.password.
			)
		db.session.add(user)
		db.session.commit()
		token = user.generate_confirmation_token()
		send_email(user.email, 'Confirm Your Account',
			'auth/email/confirm', user=user, token=token)
		flash('A confirmation mail has been sent to you by email')
		return redirect(url_for('main.index'))
	return render_template('auth/register.html', form=form)

@auth.route('/confirm/<token>')
def confirm(token):
	if current_user.confirmed:
		return redirect(url_for('main.index'))
	if current_user.confirm(token):
		flash('You have confirmed your account, Thank you!')
	else:
		flash('The confirmation link is either invalid or expired.')
	return redirect(url_for('main.index'))

@auth.route('/unconfirmed')
def unconfirmed():
	if current_user.is_anonymous or current_user.confirmed:
		return redirect(url_for('main.index'))
	return render_template('auth/unconfirmed.html')

@auth.route('/confirm')
@login_required
def resend_confirm():
	toke = current_user.generate_confirmation_token()
	send_email(user.email, 'Confirm your account',
		'auth/email/confirm', user=user, token=token)
	flash('A new confirmation email has been sent to you by email.')
	return redirect(url_for('main.index'))