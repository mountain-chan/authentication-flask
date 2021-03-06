import os

os_env = os.environ


class Config(object):
    SECRET_KEY = '3nF3Rn0'
    APP_DIR = os.path.abspath(os.path.dirname(__file__))  # This directory
    PROJECT_ROOT = os.path.abspath(os.path.join(APP_DIR, os.pardir))


class ProdConfig(Config):
    """Production configuration."""
    # app config
    ENV = 'prod'
    DEBUG = False
    DEBUG_TB_ENABLED = False  # Disable Debug toolbar
    HOST = '0.0.0.0'
    TEMPLATES_AUTO_RELOAD = False
    # JWT Config
    JWT_SECRET_KEY = '1234567a@'
    JWT_BLACKLIST_ENABLED = True
    JWT_BLACKLIST_TOKEN_CHECKS = ['access', 'refresh']
    # msql
    SQLALCHEMY_DATABASE_URI = 'mysql://root:1234567aA@@localhost/htc_temp'
    SQLALCHEMY_TRACK_MODIFICATIONS = True
    # REDIS
    REDIS_URL = "redis://:1234567aA@@localhost:6379/1"


class DevConfig(Config):
    """Production configuration."""
    # app config
    ENV = 'prod'
    DEBUG = False
    DEBUG_TB_ENABLED = False  # Disable Debug toolbar
    HOST = '0.0.0.0'
    TEMPLATES_AUTO_RELOAD = False
    # JWT Config
    JWT_SECRET_KEY = '1234567a@'
    JWT_BLACKLIST_ENABLED = True
    JWT_BLACKLIST_TOKEN_CHECKS = ['access', 'refresh']
    # msql
    SQLALCHEMY_DATABASE_URI = 'mysql://root:1234567aA@@localhost/htc_temp2'
    SQLALCHEMY_TRACK_MODIFICATIONS = True
    # REDIS
    REDIS_URL = "redis://:1234567aA@@localhost:6379/1"
