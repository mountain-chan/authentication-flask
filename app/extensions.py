import redis
from flask_login import LoginManager
from flask_marshmallow import Marshmallow
from webargs.flaskparser import FlaskParser
from flask_jwt_extended import JWTManager
from logging.handlers import RotatingFileHandler
from flask_sqlalchemy import SQLAlchemy

parser = FlaskParser()
jwt = JWTManager()
app_log_handler = RotatingFileHandler('logs/app.log', maxBytes=1000000, backupCount=30)
red = redis.StrictRedis(host='localhost', port=6379, password='1234567aA@', decode_responses=True)
db = SQLAlchemy()
ma = Marshmallow()
login_manager = LoginManager()
