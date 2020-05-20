import os
import uuid
from datetime import timedelta

from flask_login import login_required
from jsonschema import validate
from flask import Blueprint, request
from werkzeug.security import safe_str_cmp, check_password_hash
from werkzeug.utils import secure_filename

from app.api.decorators import permission_required
from app.jsonschema import schema_user_create, schema_user_update, schema_password
from app.enums import PATH_AVATAR, PATH_AVATAR_CLIENT, DEFAULT_AVATAR
from app.models import User, Group, user_schema, users_schema, user_include_pass_schema, Permission
from app.utils import parse_req, FieldString, send_result, send_error, hash_password, get_datetime_now_s, \
    allowed_file_img
from app.extensions import db, red
from flask_jwt_extended import (
    jwt_required,
    get_jwt_identity,
    get_raw_jwt)

ACCESS_EXPIRES = timedelta(days=30)
revoked_store = red

api = Blueprint('users', __name__)


@api.route('', methods=['POST'])
@jwt_required
@login_required
@permission_required(Permission.USER_MANAGEMENT)
def create_user():
    """ This is api for the user management registers user.

        Request Body:
            username: string, require
                The username of the user. Max length accepted is 50 and minimum length is 1.

            password: string, require
                The password of the user wanted to log in. Max length accepted is 50 and minimum length is 1.

            group_id: string, require
                The group id of the user wanted to join in.

        Returns:

            username: string
                username of newly registered user.

            group_id: string
                group id of this new user.

        Examples::

            curl --location --request POST 'http://<sv_address>:5012/api/v1/users' --header 'Authorization: Bearer <access_token>'
    """

    params = {
        'username': FieldString(requirement=True),
        'password': FieldString(requirement=True),
        'group_id': FieldString(requirement=True)
    }

    try:
        json_data = parse_req(params)
        # Check valid params
        validate(instance=json_data, schema=schema_user_create)

        username = json_data.get('username', None)
        password = json_data.get('password', None)
        group_id = json_data.get('group_id', None)
    except Exception as ex:
        return send_error(message="Parameters error:" + str(ex))

    row = User.query.filter_by(username=username).first()
    if row is not None:
        return send_error(message='The user name has existed!')

    try:
        row = Group.query.get(group_id)
    except Exception as ex:
        return send_error(message=str(ex))
    if row is None:
        return send_error(message='Not found the user group')

    create_date = get_datetime_now_s()
    _id = str(uuid.uuid1())

    new_values = User(id=_id, username=username, password_hash=hash_password(password),
                      create_date=create_date, group_id=group_id)
    try:
        db.session.add(new_values)
        db.session.commit()
    except Exception as ex:
        return send_error(message=str(ex))

    data = {
        'username': username,
        'group_id': group_id
    }

    return send_result(data=data, message="Create user successfully!")


"""
Function: Update user's profile - Admin right required
Input: user_id, firstname, lastname, title, group_id, mobile, address, company
Output: Success / Error Message
"""


@api.route('/<user_id>', methods=['PUT'])
@jwt_required
@login_required
@permission_required(Permission.USER_MANAGEMENT)
def update_user(user_id):
    try:
        user = User.query.get(user_id)
    except Exception as ex:
        return send_error(message="Database error:" + str(ex))
    if user is None:
        return send_error(message='Not found user to update!')

    params = {
        'firstname': FieldString(),
        'lastname': FieldString(),
        'title': FieldString(),
        'company': FieldString(),
        'mobile': FieldString(),
        'address': FieldString(),
        'group_id': FieldString()
    }
    try:
        json_data = parse_req(params)
        # Check valid params
        validate(instance=json_data, schema=schema_user_update)

        company = json_data.get('company', None)
        mobile = json_data.get('mobile', None)
        address = json_data.get('address', None)
        title = json_data.get('title', None)
        firstname = json_data.get('firstname', None)
        lastname = json_data.get('lastname', None)
        group_id = json_data.get('group_id', None)
    except Exception as ex:
        return send_error(message=str(ex))

    if group_id:
        try:
            row = Group.query.get(group_id)
        except Exception as ex:
            return send_error(message=str(ex))
        if row is None:
            return send_error(message='Not found the user group')

    modified_by = get_jwt_identity()
    modified_date = get_datetime_now_s()

    try:
        if company:
            user.company = company
        if mobile:
            user.mobile = mobile
        if address:
            user.address = address
        if firstname:
            user.firstname = firstname
        if lastname:
            user.lastname = lastname
        if title:
            user.title = title
        if group_id:
            user.group_id = group_id
        user.modified_by = modified_by
        user.modified_date = modified_date
        db.session.commit()
    except Exception as ex:
        return send_error(message=str(ex))

    data = {
        'firstname': firstname,
        'lastname': lastname,
        'title': title,
        'group_id': group_id,
        'company': company,
        'mobile': mobile,
        'address': address
    }

    return send_result(data=data, message="Update user successfully!")


@api.route('/profile', methods=['PUT'])
@jwt_required
@login_required
def update_info():
    user_id = get_jwt_identity()
    try:
        user = User.query.get(user_id)
    except Exception as ex:
        return send_error(message="Database error:" + str(ex))
    if user is None:
        return send_error(message='Not found user to update!')

    params = {
        'firstname': FieldString(),
        'lastname': FieldString(),
        'title': FieldString(),
        'mobile': FieldString(),
        'address': FieldString(),
        'company': FieldString()
    }
    try:
        json_data = parse_req(params)
        # Check valid params
        validate(instance=json_data, schema=schema_user_update)

        company = json_data.get('company', None)
        mobile = json_data.get('mobile', None)
        address = json_data.get('address', None)
        title = json_data.get('title', None)
        firstname = json_data.get('firstname', None)
        lastname = json_data.get('lastname', None)
    except Exception as ex:
        return send_error(message=str(ex))

    modified_date = get_datetime_now_s()

    try:
        if company:
            user.company = company
        if mobile:
            user.mobile = mobile
        if address:
            user.address = address
        if firstname:
            user.firstname = firstname
        if lastname:
            user.lastname = lastname
        if title:
            user.title = title
        user.modified_by = user_id
        user.modified_date = modified_date
        db.session.commit()
    except Exception as ex:
        return send_error(message=str(ex))

    data = {
        'firstname': firstname,
        'lastname': lastname,
        'company': company,
        'mobile': mobile,
        'address': address,
        'title': title
    }

    return send_result(data=data, message="Update user successfully!")


@api.route('/change_password', methods=['PUT'])
@jwt_required
@login_required
def change_password():
    user_id = get_jwt_identity()
    try:
        user = User.query.get(user_id)
    except Exception as ex:
        return send_error(message="Database error:" + str(ex))
    if user is None:
        return send_error(message='Not found user to update!')

    params = {
        'current_password': FieldString(requirement=True),
        'new_password': FieldString(requirement=True)
    }
    try:
        json_data = parse_req(params)
        # Check valid params
        validate(instance=json_data, schema=schema_password)

        current_password = json_data.get('current_password', None)
        new_password = json_data.get('new_password', None)
    except Exception as ex:
        return send_error(message=str(ex))

    user_json = user_include_pass_schema.dump(user).data
    if not check_password_hash(user_json['password_hash'], current_password):
        return send_error(message='Current password incorrect!')

    modified_date = get_datetime_now_s()

    try:
        user.password = hash_password(new_password)
        user.force_change_password = False
        user.modified_by = user_id
        user.modified_date = modified_date
        db.session.commit()
    except Exception as ex:
        return send_error(message=str(ex))

    """
    Add token to blacklist
    :return:
    """
    jti = get_raw_jwt()['jti']
    revoked_store.set(jti, 'true', ACCESS_EXPIRES * 1.2)

    data = {
    }

    return send_result(data=data, message="Change password successfully!")


@api.route('/<user_id>/reset_password', methods=['PUT'])
@jwt_required
@login_required
@permission_required(Permission.USER_MANAGEMENT)
def reset_password(user_id):
    try:
        user = User.query.get(user_id)
    except Exception as ex:
        return send_error(message="Database error:" + str(ex))
    if user is None:
        return send_error(message='Not found user to update!')

    params = {
        'new_password': FieldString(requirement=True)
    }
    try:
        json_data = parse_req(params)
        # Check valid params
        validate(instance=json_data, schema=schema_password)

        new_password = json_data.get('new_password', None)
    except Exception as ex:
        return send_error(message=str(ex))

    modified_date = get_datetime_now_s()
    modified_by = get_jwt_identity()

    try:
        user.password = hash_password(new_password)
        user.force_change_password = True
        user.modified_by = modified_by
        user.modified_date = modified_date
        db.session.commit()
    except Exception as ex:
        return send_error(message=str(ex))

    user_json = user_schema.dump(user).data
    data = {
    }

    return send_result(data=data, message="Reset password successfully!")


@api.route('/<user_id>', methods=['DELETE'])
@jwt_required
@login_required
@permission_required(Permission.USER_MANAGEMENT)
def delete_user(user_id):
    user = User.query.get(user_id)
    if user is None:
        return send_error(message='Not found user to delete!')

    try:
        db.session.delete(user)
        db.session.commit()
    except Exception as ex:
        return send_error(message=str(ex))

    user = user_schema.dump(user).data

    return send_result(data=user, message="Delete user successfully!")


@api.route('/<user_id>/deactivate', methods=['DELETE'])
@jwt_required
@login_required
@permission_required(Permission.USER_MANAGEMENT)
def deactivate(user_id):
    user = User.query.get(user_id)
    if user is None:
        return send_error(message='Not found user to deactivate!')

    try:
        user.is_active = True
        db.session.commit()
    except Exception as ex:
        return send_error(message=str(ex))

    user = user_schema.dump(user).data
    user['is_active'] = False

    return send_result(data=user, message="Deactivate user successfully!")


@api.route('/<user_id>/activate', methods=['GET'])
@jwt_required
@login_required
@permission_required(Permission.USER_MANAGEMENT)
def activate(user_id):
    user = User.query.get(user_id)
    if user is None:
        return send_error(message='Not found user to Activate!')

    try:
        user.is_active = False
        db.session.commit()
    except Exception as ex:
        return send_error(message=str(ex))

    user = user_schema.dump(user).data
    user['is_active'] = True

    return send_result(data=user, message="Activate user successfully!")


@api.route('', methods=['GET'])
@jwt_required
@login_required
def get_all_users():
    try:
        list_items = User.query.all()
    except Exception as ex:
        return send_error(message=str(ex))
    results = users_schema.dump(list_items).data

    return send_result(data=results)


@api.route('/<user_id>', methods=['GET'])
@jwt_required
@login_required
def get_user_by_id(user_id):
    try:
        item = User.query.get(user_id)
    except Exception as ex:
        return send_error(message=str(ex))
    user = user_schema.dump(item).data

    return send_result(data=user)


@api.route('/profile', methods=['GET'])
@jwt_required
@login_required
def get_profile():
    user_id = get_jwt_identity()
    try:
        item = User.query.get(user_id)
    except Exception as ex:
        return send_error(message=str(ex))
    user = user_schema.dump(item).data

    return send_result(data=user)


@api.route('/change_avatar', methods=['POST'])
@jwt_required
def change_avatar():
    user_id = request.args.get('user_id')

    user = User.query.get(user_id)
    if user is None:
        return send_error(message='Not found user to change avatar!')

    user_json = user_schema.dump(user).data
    try:
        image_file = request.files['image_file']
    except Exception as ex:
        return send_error(message='No file chosen' + str(ex))

    if not allowed_file_img(image_file.filename):
        return send_error(message="Allowed files image: png, jpg, jpeg, gif")

    """
    delete old avatar
    """
    if user_json['avatar_path'] is not None and user_json['avatar_path'] != "":
        try:
            file_name = user_json['avatar_path'].rsplit('/', 1)[1]
            if not safe_str_cmp(file_name, DEFAULT_AVATAR):
                os.remove(os.path.join(PATH_AVATAR, file_name))
        except Exception:
            pass

    filename = user_json['account_name'] + image_file.filename
    filename = secure_filename(filename)

    path = os.path.join(PATH_AVATAR, filename)
    path_client = os.path.join(PATH_AVATAR_CLIENT, filename)
    try:
        image_file.save(path)
    except Exception as ex:
        return send_error(message="Save file error: " + str(ex))

    try:
        user.avatar_path = path_client
        db.session.commit()
    except Exception as ex:
        return send_error(message=str(ex))

    return send_result(message="Change avatar successfully!")


@api.route('/upload_file_avatar', methods=['POST'])
@jwt_required
def upload_file_avatar():
    user_id = get_jwt_identity()
    row = User.query.get(user_id)
    if row is None:
        return send_error(message='Error database!')

    user = user_schema.dump(row).data
    try:
        image_file = request.files['image_file']
    except Exception as ex:
        return send_error(message='No file chosen' + str(ex))

    if not allowed_file_img(image_file.filename):
        return send_error(message="Allowed files image: png, jpg, jpeg, gif")

    filename = str(int(get_datetime_now_s())) + user['id'] + image_file.filename
    filename = secure_filename(filename)

    path = os.path.join(PATH_AVATAR, filename)
    path_client = os.path.join(PATH_AVATAR_CLIENT, filename)
    try:
        image_file.save(path)
    except Exception as ex:
        return send_error(message="Save file error: " + str(ex))

    data = {'filename': filename, 'avatar_path': path_client}
    return send_result(data=data)


@api.route('/delete_file_avatar', methods=['DELETE'])
@jwt_required
def delete_file_avatar():
    file_name = request.args.get('file_name')

    if not safe_str_cmp(file_name, DEFAULT_AVATAR):
        try:
            os.remove(os.path.join(PATH_AVATAR, file_name))
        except Exception as ex:
            return send_error(message='Delete error' + str(ex))

    return send_result(message="Delete file successfully!")
