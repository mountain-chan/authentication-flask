# -*- coding: utf-8 -*-
import logging
import traceback
from time import strftime
from flask import Flask, request
from app.api import v1 as api_v1
from app.extensions import jwt, app_log_handler, db, ma, login_manager
from .settings import ProdConfig
from .utils import send_error


def create_app(config_object=ProdConfig):
    """Init App Register Application extensions and API prefix

    Args:
        config_object: We will use Prod Config when the environment variable has FLASK_DEBUG=1.
        You can run export FLASK_DEBUG=1 in order to run in application dev mode.
        You can see config_object in the settings.py file
    """
    app = Flask(__name__, static_url_path="", static_folder="./files", template_folder="./template")
    app.config.from_object(config_object)
    register_extensions(app)
    register_blueprints(app)
    return app


def register_extensions(app):
    """Init extension. You can see list extension in the extensions.py

    Args:
        app: Flask handler application
    """
    # Order matters: Initialize SQLAlchemy before Marshmallow
    db.init_app(app)
    ma.init_app(app)
    jwt.init_app(app)
    login_manager.init_app(app)
    # logger
    logger = logging.getLogger('api')
    logger.setLevel(logging.INFO)
    logger.addHandler(app_log_handler)

    @app.after_request
    def after_request(response):
        # This IF avoids the duplication of registry in the log,
        # since that 500 is already logged via @app.errorhandler.
        if response.status_code != 500:
            ts = strftime('[%Y-%b-%d %H:%M]')
            logger.error('%s %s %s %s %s %s',
                         ts,
                         request.remote_addr,
                         request.method,
                         request.scheme,
                         request.full_path,
                         response.status)
        return response

    @app.errorhandler(Exception)
    def exceptions(e):
        ts = strftime('[%Y-%b-%d %H:%M]')
        tb = traceback.format_exc()
        error = '{} {} {} {} {} {} 5xx INTERNAL SERVER ERROR\n{}'.format \
            (
                ts,
                request.remote_addr,
                request.method,
                request.scheme,
                request.full_path,
                tb,
                str(e)
            )

        logger.error(error)

        return send_error(message='INTERNAL SERVER ERROR', code=500)


def register_blueprints(app):
    """Init blueprint for api url

    :param app: Flask application
    """
    app.register_blueprint(api_v1.auth.api, url_prefix='/api/v1/auth')
    app.register_blueprint(api_v1.user.api, url_prefix='/api/v1/users')
    app.register_blueprint(api_v1.group.api, url_prefix='/api/v1/groups')
    app.register_blueprint(api_v1.permission.api, url_prefix='/api/v1/permissions')
    app.register_blueprint(api_v1.security_policy.api, url_prefix='/api/v1/security_policies')
