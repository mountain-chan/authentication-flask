from flask_login import login_required
from jsonschema import validate
from flask import Blueprint
from marshmallow import fields

from app.api.decorators import permission_required
from app.jsonschema import schema_security_policy
from app.models import SecurityPolicy, security_policy_schema, Permission
from app.utils import parse_req, send_result, send_error, get_datetime_now_s
from app.extensions import db
from flask_jwt_extended import (
    jwt_required,
    get_jwt_identity
)

api = Blueprint('security_policies', __name__)


@api.route('', methods=['GET'])
@jwt_required
@login_required
def get():
    try:
        setting = SecurityPolicy.query.first()
    except Exception as ex:
        return send_error(message=str(ex))
    results = security_policy_schema.dump(setting).data
    return send_result(data=results)


@api.route('', methods=['PUT'])
@jwt_required
@login_required
@permission_required(Permission.USER_MANAGEMENT)
def update():
    params = {
        'login_failed_attempts': fields.Number(),
        'logout_after_inactivate': fields.Number(),
        'password_expiration': fields.Number(),
        'password_password_min_length': fields.Number(),
        'password_min_length': fields.Number(),
        'password_include_symbol': fields.Bool(),
        'password_include_number': fields.Bool(),
        'password_include_lower_case': fields.Bool(),
        'password_include_upper_case': fields.Bool(),
    }
    try:
        json_data = parse_req(params)
        # Check valid params
        validate(instance=json_data, schema=schema_security_policy)

        login_failed_attempts = json_data.get('login_failed_attempts', None)
        logout_after_inactivate = json_data.get('logout_after_inactivate', None)
        password_expiration = json_data.get('password_expiration', None)
        password_min_length = json_data.get('password_min_length', None)
        password_include_symbol = json_data.get('password_include_symbol', None)
        password_include_number = json_data.get('password_include_number', None)
        password_include_lower_case = json_data.get('password_include_lower_case', None)
        password_include_upper_case = json_data.get('password_include_upper_case', None)

    except Exception as ex:
        return send_error(message=str(ex))

    try:
        setting = SecurityPolicy.query.first()
    except Exception as ex:
        return send_error(message=str(ex))

    modified_by = get_jwt_identity()
    modified_date = get_datetime_now_s()

    try:
        if login_failed_attempts:
            setting.login_failed_attempts = login_failed_attempts
        if logout_after_inactivate:
            setting.logout_after_inactivate = logout_after_inactivate
        if password_expiration:
            setting.password_expiration = password_expiration
        if password_min_length:
            setting.password_min_length = password_min_length
        if password_include_symbol:
            setting.password_include_symbol = password_include_symbol
        if password_include_number:
            setting.password_include_number = password_include_number
        if password_include_lower_case:
            setting.password_include_lower_case = password_include_lower_case
        if password_include_upper_case:
            setting.password_include_upper_case = password_include_upper_case
        setting.modified_by = modified_by
        setting.modified_date = modified_date
        db.session.commit()
    except Exception as ex:
        return send_error(message=str(ex))

    data = {
        'login_failed_attempts': login_failed_attempts,
        'logout_after_inactivate': logout_after_inactivate,
        'password_expiration': password_expiration,
        'password_min_length': password_min_length,
        'password_include_symbol': password_include_symbol,
        'password_include_number': password_include_number,
        'password_include_lower_case': password_include_lower_case,
        'password_include_upper_case': password_include_upper_case,
    }

    return send_result(data=data, message="Update security policy successfully!")


@api.route('/multiple', methods=['PUT'])
@jwt_required
@login_required
@permission_required(Permission.USER_MANAGEMENT)
def update_multiple():
    params = {
        'login_failed_attempts': fields.Number(),
        'logout_after_inactivate': fields.Number(),
        'password_expiration': fields.Number(),
        'password_password_min_length': fields.Number(),
        'password_min_length': fields.Number(),
        'password_include_symbol': fields.Bool(),
        'password_include_number': fields.Bool(),
        'password_include_lower_case': fields.Bool(),
        'password_include_upper_case': fields.Bool(),
    }
    try:
        json_data = parse_req(params)
        # Check valid params
        validate(instance=json_data, schema=schema_security_policy)

        login_failed_attempts = json_data.get('login_failed_attempts', None)
        logout_after_inactivate = json_data.get('logout_after_inactivate', None)
        password_expiration = json_data.get('password_expiration', None)
        password_min_length = json_data.get('password_min_length', None)
        password_include_symbol = json_data.get('password_include_symbol', None)
        password_include_number = json_data.get('password_include_number', None)
        password_include_lower_case = json_data.get('password_include_lower_case', None)
        password_include_upper_case = json_data.get('password_include_upper_case', None)

    except Exception as ex:
        return send_error(message=str(ex))

    modified_by = get_jwt_identity()
    modified_date = get_datetime_now_s()

    try:
        db.session.query(SecurityPolicy).update(
            {SecurityPolicy.login_failed_attempts: login_failed_attempts,
             SecurityPolicy.logout_after_inactivate: logout_after_inactivate,
             SecurityPolicy.password_expiration: password_expiration,
             SecurityPolicy.password_min_length: password_min_length,
             SecurityPolicy.password_include_symbol: password_include_symbol,
             SecurityPolicy.password_include_number: password_include_number,
             SecurityPolicy.password_include_lower_case: password_include_lower_case,
             SecurityPolicy.password_include_upper_case: password_include_upper_case,
             SecurityPolicy.modified_by: modified_by, SecurityPolicy.modified_date: modified_date},
            synchronize_session=False)
        db.session.commit()
    except Exception as ex:
        return send_error(message=str(ex))

    data = {
        'login_failed_attempts': login_failed_attempts,
        'logout_after_inactivate': logout_after_inactivate,
        'password_expiration': password_expiration,
        'password_min_length': password_min_length,
        'password_include_symbol': password_include_symbol,
        'password_include_number': password_include_number,
        'password_include_lower_case': password_include_lower_case,
        'password_include_upper_case': password_include_upper_case,
    }

    return send_result(data=data, message="Update security policy successfully!")
