from datetime import timedelta
from flask import Blueprint
from flask_login import login_user, logout_user, login_required
from werkzeug.security import check_password_hash
from app.extensions import jwt, red
from app.models import User, Group, user_group_schema, SecurityPolicy, security_policy_schema, \
    PermissionDetail, list_permissions_schema, user_include_pass_schema
from app.utils import parse_req, FieldString, send_result, send_error
from flask_jwt_extended import (
    jwt_required, create_access_token,
    jwt_refresh_token_required, get_jwt_identity,
    create_refresh_token, get_raw_jwt, get_jti
)

ACCESS_EXPIRES = timedelta(days=30)
REFRESH_EXPIRES = timedelta(days=30)
revoked_store = red
api = Blueprint('auth', __name__)


@api.route('/login', methods=['POST'])
def login():
    """ This is controller of the login api.

    Request Body:
        username: string, require
            The username of the user. Max length accepted is 50 and minimum length is 1

        password: string, require
            The password of the user wanted to log in. Max length accepted is 50 and minimum length is 1

    Returns:

        access_token: string
            your access token. you needed to save this to access to backend services. Please put
            access_token to Header Authorization: Bearer <accees_token>

        force_change_password: boolean
            When true. The user have force change password after login.

        group: string
            Current group of the user

        list_permissions: list[string,]
            Mapping action and resource user can access. For example create_user or get_users

        login_failed_attempts: number
            Number login failed of the current user.

        logout_after_inactivate: number
            Number in seconds. If user do not have any action in the period time. Use will be logged out

        refresh_token: string
            Token use to refresh expire time of the access token. Please put
            refresh_token to Header Authorization: Bearer <refresh_token>

    Examples::

        curl --location --request GET 'http://<sv_address>:5012/api/v1/users/4658df34-8630-11ea-b850-588a5a158009' --header 'Authorization: Bearer <refresh_token>'

    """
    params = {
        'username': FieldString(),
        'password': FieldString()
    }

    try:
        json_data = parse_req(params)
        username = json_data.get('username', None).lower()
        password = json_data.get('password')
    except Exception as ex:
        return send_error(message='json_parser_error' + str(ex))

    row = User.query.filter_by(username=username).first()
    if row is None:
        return send_error(message='Username or password incorrect!')

    user = user_include_pass_schema.dump(row).data

    if not check_password_hash(user['password_hash'], password):
        return send_error(message='Username or password incorrect!')

    if not login_user(row):
        return send_error(message="User is not activate!")

    access_token = create_access_token(identity=user['id'], expires_delta=ACCESS_EXPIRES)
    refresh_token = create_refresh_token(identity=user['id'], expires_delta=REFRESH_EXPIRES)
    access_jti = get_jti(encoded_token=access_token)
    refresh_jti = get_jti(encoded_token=refresh_token)
    revoked_store.set(access_jti, 'false', ACCESS_EXPIRES * 1.2)
    revoked_store.set(refresh_jti, 'false', REFRESH_EXPIRES * 1.2)

    # get group name of this user
    try:
        group = Group.query.get(user['group_id'])
    except Exception as ex:
        return send_error(message="Database error:" + str(ex))

    group_json = user_group_schema.dump(group).data
    group_name = ''
    if group:
        group_name = group_json['name']

    try:
        setting = SecurityPolicy.query.first()
    except Exception as ex:
        return send_error(message=str(ex))
    security_policy = security_policy_schema.dump(setting).data

    """
    Find list permissions of current group
    """
    try:
        list_items = PermissionDetail.query.all()
    except Exception as ex:
        return send_error(message=str(ex))
    list_permissions = list_permissions_schema.dump(list_items).data

    data = {
        'access_token': access_token,
        'refresh_token': refresh_token,
        'logout_after_inactivate': security_policy['logout_after_inactivate'],
        'login_failed_attempts': security_policy['login_failed_attempts'],
        'username': user['username'],
        'force_change_password': user['force_change_password'],
        'group': group_name,
        'list_permissions': list_permissions
    }

    return send_result(data=data, message='Logged in successfully!')


# The jwt_refresh_token_required decorator insures a valid refresh
# token is present in the request before calling this endpoint. We
# can use the get_jwt_identity() function to get the identity of
# the refresh token, and use the create_access_token() function again
# to make a new access token for this identity.
@api.route('/refresh', methods=['POST'])
@jwt_refresh_token_required
@login_required
def refresh():
    """This api use for refresh expire time of the access token. Please inject the refresh token in Authorization header

    Args:
        refresh_token : string, require
            If True, will return the parameters for this estimator and
            contained subobjects that are estimators.
    Returns:
        access_token : new access token
    """
    current_user_id = get_jwt_identity()
    access_token = create_access_token(identity=current_user_id)
    access_jti = get_jti(encoded_token=access_token)
    revoked_store.set(access_jti, 'false', ACCESS_EXPIRES * 1.2)

    ret = {
        'access_token': access_token
    }
    return send_result(data=ret)


# Endpoint for revoking the current users access token
@api.route('/logout', methods=['DELETE'])
@jwt_required
@login_required
def logout():
    """
    Add token to blacklist
    :return:
    """
    jti = get_raw_jwt()['jti']
    revoked_store.set(jti, 'true', ACCESS_EXPIRES * 1.2)
    logout_user()

    return send_result(message='logout successfully')


# Endpoint for revoking the current users refresh token
@api.route('/logout2', methods=['DELETE'])
@jwt_refresh_token_required
def logout2():
    jti = get_raw_jwt()['jti']
    revoked_store.set(jti, 'true', REFRESH_EXPIRES * 1.2)
    return send_result(message='logout_successfully')


# check token revoked_store
@jwt.token_in_blacklist_loader
def check_if_token_is_revoked(decrypted_token):
    jti = decrypted_token['jti']
    entry = revoked_store.get(jti)
    if entry is None:
        return True
    return False
