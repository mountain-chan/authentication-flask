import json
import uuid

from flask_login import login_required
from jsonschema import validate
from flask import Blueprint, request

from app.api.decorators import permission_required
from app.jsonschema import schema_group
from app.models import Group, user_groups_schema, user_group_schema, \
    Permission
from app.utils import parse_req, FieldString, send_result, send_error, get_datetime_now_s
from app.extensions import db
from flask_jwt_extended import (
    jwt_required,
    get_jwt_identity
)

api = Blueprint('groups', __name__)


@api.route('', methods=['POST'])
@jwt_required
@login_required
@permission_required(Permission.USER_MANAGEMENT)
def post():
    params = {
        'name': FieldString(requirement=True)
    }

    try:
        json_data = parse_req(params)
        # Check valid params
        validate(instance=json_data, schema=schema_group)

        name = json_data.get('name', None)
    except Exception as ex:
        return send_error(message="Parameters error:" + str(ex))

    row = Group.query.filter_by(name=name).first()
    if row is not None:
        return send_error(message='The group name has existed!')

    create_date = get_datetime_now_s()
    _id = str(uuid.uuid1())

    new_group = Group(id=_id, name=name, create_date=create_date)
    try:
        db.session.add(new_group)
        db.session.commit()
    except Exception as ex:
        return send_error(message=str(ex))

    data = {
        'name': name
    }

    return send_result(data=data, message="Create the group successfully!")


@api.route('/<group_id>', methods=['PUT'])
@jwt_required
@login_required
@permission_required(Permission.USER_MANAGEMENT)
def put(group_id):
    try:
        group = Group.query.get(group_id)
    except Exception as ex:
        return send_error(message="Database error:" + str(ex))
    if group is None:
        return send_error(message='Not found group to update!')

    params = {
        'name': FieldString(requirement=True),
    }
    try:
        json_data = parse_req(params)
        # Check valid params
        validate(instance=json_data, schema=schema_group)

        name = json_data.get('name', None)
    except Exception as ex:
        return send_error(message="Parameters error:" + str(ex))

    try:
        row = Group.query.filter(Group.name == name, Group.id != group_id).first()
    except Exception as ex:
        return send_error(message=str(ex))
    if row is not None:
        return send_error(message='The group name has existed!')

    modified_by = get_jwt_identity()
    modified_date = get_datetime_now_s()

    try:
        group.name = name
        group.modified_by = modified_by
        group.modified_date = modified_date
        db.session.commit()
    except Exception as ex:
        return send_error(message=str(ex))

    data = {
        'new name': name
    }

    return send_result(data=data, message="Update group successfully!")


@api.route('/<group_id>', methods=['DELETE'])
@jwt_required
@login_required
@permission_required(Permission.USER_MANAGEMENT)
def delete(group_id):
    try:
        get_group = Group.query.get(group_id)
    except Exception as ex:
        return send_error(message="Database error: " + str(ex))
    if get_group is None:
        return send_error(message='Not found group to delete!')

    try:
        db.session.delete(get_group)
        db.session.commit()
    except Exception as ex:
        return send_error(message=str(ex))

    group_json = user_group_schema.dump(get_group).data

    return send_result(data=group_json, message="Delete group successfully!")


@api.route('', methods=['GET'])
@jwt_required
@login_required
def get_all_groups():
    try:
        list_items = Group.query.all()
    except Exception as ex:
        return send_error(message="Get all error: " + str(ex))

    results = user_groups_schema.dump(list_items).data

    return send_result(data=results)


@api.route('/<group_id>', methods=['GET'])
@jwt_required
@login_required
def get_group_by_id(group_id):
    try:
        item = Group.query.get(group_id)
    except Exception as ex:
        return send_error(message=str(ex))

    group = user_group_schema.dump(item).data

    return send_result(data=group)

# @api.route('/<group_id>/add_permissions', methods=['GET'])
# @jwt_required
# def add_permissions(group_id):
#     try:
#         row = Group.query.get(group_id)
#     except Exception as ex:
#         return send_error(message=str(ex))
#     if row is None:
#         return send_error(message='Not found group to add permissions!')
#
#     try:
#         list_permissions = request.args.get('list_permissions')
#     except Exception as ex:
#         return send_error("Not found list_permissions parameter: " + str(ex))
#
#     """
#     Reset all permissions of current group
#     """
#     try:
#         stm = GroupPermission.__table__.delete().where(GroupPermission.groups_id == group_id)
#         db.session.execute(stm)
#         db.session.commit()
#     except Exception as ex:
#         return send_error(message='Reset error: ' + str(ex))
#
#     """
#     Insert each access in list_permissions
#     """
#     list_permissions = json.loads(list_permissions)
#     for permission in list_permissions:
#         new_value = GroupPermission(group_id=group_id, permission_id=permission['id'])
#         try:
#             db.session.add(new_value)
#         except Exception as ex:
#             return send_error(message='Insert error: ' + str(ex))
#
#     db.session.commit()
#     return send_result(message="Add permissions successfully!")
