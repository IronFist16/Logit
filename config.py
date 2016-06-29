import os

basedir = os.path.abspath(os.path.dirname(__file__))

class Config:

	SECRET_KEY = os.environ.get('SECRET_KEY') or 'Need to Generate SECRET_KEY'
	SQLALCHEMY_COMMIT_ON_TEARDOWN = True
	LOGIT_MAIL_SUBJECT_PREFIX = '[LOGIT]'
	LOGIT_MAIL_SENDER = 'Logit Admin <logit.admin@gmail.com'
	LOGIT_ADMIN = os.environ.get('LOGIT_ADMIN')

	@staticmethod
	def init_app(app):
		pass

class DevelopmentConfig(Config):

	print('Development Environment Setup')

	DEBUG = True
	PORT = 5001
	MAIL_SERVER = 'smtp.googlemail.com'
	MAIL_PORT = 587
	MAIL_USE_TLS = True
	MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
	MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
	SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URL') or \
	'sqlite:///' + os.path.join(basedir, 'data-dev.sqlite')

class TestingConfig(Config):

	print('Testing Environment Setup')

	TESTING = True
	SQLALCHEMY_DATABASE_URI = os.environ.get('TEST_DATABASE_URL') or \
	'sqlite:///' + os.path.join(basedir, 'data-test.sqlite')

class ProductionConfig(Config):

	print('Production Environment Setup')

	SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
	'sqlite:///' + os.path.join(basedir, 'data.sqlite')

config = {
	'development':DevelopmentConfig,
	'testing':TestingConfig,
	'production':ProductionConfig,
	'default':DevelopmentConfig
}
