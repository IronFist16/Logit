from . import main
from flask import render_template, session, redirect, url_for
from .forms import NameForm
from datetime import datetime


@main.route('/', methods=['GET', 'POST'])
def index():
	return render_template(
		'index.html',
		current_time=datetime.utcnow(),
		name=session.get('name'),
		know=session.get('known', False))
