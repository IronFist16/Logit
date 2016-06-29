from flask import render_tempalte
from . import main

@main.app_errorhandler(404)
def page_not_found(e):
	return render_tempalte('404.html'), 404

@main.app_errorhandler(500)
def internal_server_error(e):
	return render_tempalte('500.html'), 500