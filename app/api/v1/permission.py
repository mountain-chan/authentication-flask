import uuid

from flask_login import login_required
from jsonschema import validate
from flask import Blueprint, request

from app.api.decorators import permission_required
from app.jsonschema import schema_permission
from app.models import PermissionDetail, permissions_schema, permission_schema, Permission
from app.utils import parse_req, FieldString, send_result, send_error, get_datetime_now_s
from app.extensions import db
from flask_jwt_extended import (
    jwt_required,
    get_jwt_identity
)

api = Blueprint('permissions', __name__)


@api.route('', methods=['POST'])
@login_required
@permission_required(Permission.USER_MANAGEMENT)
@jwt_required
def post():
    params = {
        'name': FieldString(requirement=True),
        'descriptions': FieldString()
    }

    try:
        json_data = parse_req(params)
        # Check regex params
        validate(instance=json_data, schema=schema_permission)

        name = json_data.get('name', None)
        descriptions = json_data.get('descriptions', None)
    except Exception as ex:
        return send_error(message="Parameters error:" + str(ex))

    row = PermissionDetail.query.filter_by(name=name).first()
    if row is not None:
        return send_error(message='The permission name has existed!')

    create_date = get_datetime_now_s()
    _id = str(uuid.uuid1())

    new_values = PermissionDetail(id=_id, descriptions=descriptions, name=name, create_date=create_date)
    try:
        db.session.add(new_values)
        db.session.commit()
    except Exception as ex:
        return send_error(message=str(ex))

    return send_result(message="Create permission successfully!")


@api.route('/<permission_id>', methods=['PUT'])
@login_required
@permission_required(Permission.USER_MANAGEMENT)
@jwt_required
def put(permission_id):
    try:
        permission = PermissionDetail.query.get(permission_id)
    except Exception as ex:
        return send_error(message="Database error: " + str(ex))

    if permission is None:
        return send_error(message='Not found the permission to update!')

    params = {
        'name': FieldString(),
        'descriptions': FieldString()
    }
    try:
        json_data = parse_req(params)
        # Check regex params
        validate(instance=json_data, schema=schema_permission)

        descriptions = json_data.get('descriptions', None)
        name = json_data.get('name', None)
    except Exception as ex:
        return send_error(message="Parameters error:" + str(ex))

    try:
        row = PermissionDetail.query.filter(PermissionDetail.name == name, PermissionDetail.id != permission_id).first()
    except Exception as ex:
        return send_error(message=str(ex))
    if row is not None:
        return send_error(message='The permission name has existed!')

    modified_by = get_jwt_identity()
    edit_date = get_datetime_now_s()

    try:
        if descriptions:
            permission.descriptions = descriptions
        if name:
            permission.name = name
        permission.modified_by = modified_by
        permission.edit_date = edit_date
        db.session.commit()
    except Exception as ex:
        return send_error(message=str(ex))

    return send_result(message="Update permission successfully!")


@api.route('', methods=['GET'])
@jwt_required
@login_required
def get_all():
    try:
        list_items = PermissionDetail.query.all()
    except Exception as ex:
        return send_error(message=str(ex))
    results = permissions_schema.dump(list_items).data
    return send_result(data=results)


@api.route('/pagination', methods=['GET'])
@jwt_required
@login_required
def pagination():
    page_size = request.args.get('page_size', 25, type=int)
    page_number = request.args.get('page_number', 1, type=int)

    try:
        list_items = PermissionDetail.query.order_by(PermissionDetail.create_date.desc()).paginate(page=page_number,
                                                                                                   per_page=page_size)
    except Exception as ex:
        return send_error(message=str(ex))

    results = permissions_schema.dump(list_items.items).data
    data = {
        'totals': list_items.total,
        'results': results
    }

    return send_result(data=data)


@api.route('/<permission_id>', methods=['GET'])
@jwt_required
@login_required
def get_permission_by_id(permission_id):
    try:
        row = PermissionDetail.query.get(permission_id)
    except Exception as ex:
        return send_error(message=str(ex))
    rs = permission_schema.dump(row).data
    return send_result(data=rs)
