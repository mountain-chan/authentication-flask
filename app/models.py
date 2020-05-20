# coding: utf-8
import uuid

from flask_login import UserMixin

from app.extensions import db, ma, login_manager
from app.utils import hash_password

admin_group_id = ""


class Permission:
    MONITOR_MOFA = 1
    OPERATOR_MOFA = 2
    USER_MANAGEMENT = 4


class PermissionDetail(db.Model):
    __tablename__ = 'permission_details'

    id = db.Column(db.String(50), primary_key=True)
    name = db.Column(db.String(200), unique=True)
    number = db.Column(db.BigInteger, unique=True)
    descriptions = db.Column(db.Text)
    create_date = db.Column(db.BigInteger)
    created_by = db.Column(db.String(50))
    modified_date = db.Column(db.BigInteger)
    modified_by = db.Column(db.String(50))

    @staticmethod
    def insert_permissions():
        permissions = [{'name': 'MONITOR_MOFA', 'number': 1, 'description': 'View system MoFa'},
                       {'name': 'OPERATOR_MOFA', 'number': 2, 'description': 'Opera system MoFa'},
                       {'name': 'USER_MANAGEMENT', 'number': 4, 'description': 'Manage users'}]

        for row in permissions:
            permission = PermissionDetail.query.filter_by(name=row['name']).first()
            if permission is None:
                _id = str(uuid.uuid1())
                permission = PermissionDetail(id=_id, name=row['name'], number=row['number'],
                                              descriptions=row['description'])
                db.session.add(permission)
        db.session.commit()


class Group(db.Model):
    __tablename__ = 'groups'

    id = db.Column(db.String(50), primary_key=True)
    name = db.Column(db.String(200), unique=True)
    permissions = db.Column(db.BigInteger)
    default = db.Column(db.Boolean, default=False, index=True)
    create_date = db.Column(db.BigInteger)
    created_by = db.Column(db.ForeignKey('users.id'), index=True)
    modified_date = db.Column(db.BigInteger)
    modified_by = db.Column(db.ForeignKey('users.id'), index=True)

    user = db.relationship('User', primaryjoin='Group.created_by == User.id', backref='user_groups')
    user1 = db.relationship('User', primaryjoin='Group.modified_by == User.id', backref='user_groups_0')

    def __init__(self, **kwargs):
        super(Group, self).__init__(**kwargs)
        if self.permissions is None:
            self.permissions = 0

    @staticmethod
    def insert_groups():
        global admin_group_id
        groups = {
            'MoFa Monitor': [Permission.MONITOR_MOFA],
            'MoFa Operator': [Permission.MONITOR_MOFA, Permission.OPERATOR_MOFA],
            'Admin': [Permission.MONITOR_MOFA, Permission.OPERATOR_MOFA, Permission.USER_MANAGEMENT],
        }
        default_group = 'MoFa Monitor'
        for row in groups:
            group = Group.query.filter_by(name=row).first()
            if group is None:
                _id = str(uuid.uuid1())
                if row == 'Admin':
                    admin_group_id = _id
                group = Group(id=_id, name=row)
            group.reset_permissions()
            for perm in groups[row]:
                group.add_permission(perm)
            group.default = (group.name == default_group)
            db.session.add(group)
        db.session.commit()

    def add_permission(self, perm):
        if not self.has_permission(perm):
            self.permissions += perm

    def remove_permission(self, perm):
        if self.has_permission(perm):
            self.permissions -= perm

    def reset_permissions(self):
        self.permissions = 0

    def has_permission(self, perm):
        return self.permissions & perm == perm


class SecurityPolicy(db.Model):
    __tablename__ = 'security_policy'

    id = db.Column(db.String(50), primary_key=True)
    login_failed_attempts = db.Column(db.SmallInteger, server_default=db.FetchedValue())
    logout_after_inactivate = db.Column(db.BigInteger, server_default=db.FetchedValue())
    password_expiration = db.Column(db.Integer, server_default=db.FetchedValue())
    password_min_length = db.Column(db.SmallInteger, server_default=db.FetchedValue())
    password_max_length = db.Column(db.SmallInteger, server_default=db.FetchedValue())
    password_include_symbol = db.Column(db.Integer, server_default=db.FetchedValue())
    password_include_number = db.Column(db.Integer, server_default=db.FetchedValue())
    password_include_lower_case = db.Column(db.Integer, server_default=db.FetchedValue())
    password_include_upper_case = db.Column(db.Integer, server_default=db.FetchedValue())
    modified_date = db.Column(db.BigInteger)
    modified_by = db.Column(db.String(50))

    @staticmethod
    def insert_policy():
        _id = str(uuid.uuid1())
        policy = SecurityPolicy(id=_id)
        db.session.add(policy)
        db.session.commit()


class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.String(50), primary_key=True)
    username = db.Column(db.String(100), nullable=False, unique=True)
    password_hash = db.Column(db.String(255), nullable=False)
    login_failed_attempts = db.Column(db.SmallInteger, server_default=db.FetchedValue())
    firstname = db.Column(db.String(100))
    lastname = db.Column(db.String(100))
    title = db.Column(db.String(50), server_default=db.FetchedValue())
    is_active = db.Column(db.Boolean, default=True)
    group_id = db.Column(db.ForeignKey('groups.id'), index=True)
    lang = db.Column(db.String(50))
    company = db.Column(db.String(50))
    address = db.Column(db.String(255))
    mobile = db.Column(db.String(50))
    force_change_password = db.Column(db.Integer, server_default=db.FetchedValue())
    create_date = db.Column(db.BigInteger)
    created_by = db.Column(db.ForeignKey('users.id'), index=True)
    modified_date = db.Column(db.BigInteger)
    modified_by = db.Column(db.ForeignKey('users.id'), index=True)

    group = db.relationship('Group', primaryjoin='User.group_id == Group.id', backref='user_groups')
    parent = db.relationship('User', remote_side=[id], primaryjoin='User.created_by == User.id', backref='user_users')
    parent1 = db.relationship('User', remote_side=[id], primaryjoin='User.modified_by == User.id',
                              backref='user_users_0')

    @staticmethod
    def insert_user():
        user = User.query.filter_by(username='HTC Admin').first()
        if user is None:
            _id = str(uuid.uuid1())
            user = User(id=_id, username='HTC Admin', password_hash=hash_password('admin@1234'),
                        group_id=admin_group_id)
            db.session.add(user)
            db.session.commit()

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)

    def can(self, perm):
        return self.group is not None and self.group.has_permission(perm)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


class UserDisplay(db.Model):
    __tablename__ = 'users_display'

    id = db.Column(db.String(50), primary_key=True)
    username = db.Column(db.String(100), nullable=False, unique=True)
    login_failed_attempts = db.Column(db.SmallInteger, server_default=db.FetchedValue())
    firstname = db.Column(db.String(100))
    lastname = db.Column(db.String(100))
    title = db.Column(db.String(50), server_default=db.FetchedValue())
    is_active = db.Column(db.Boolean, default=True)
    group_id = db.Column(db.String(50))
    lang = db.Column(db.String(50))
    company = db.Column(db.String(50))
    address = db.Column(db.String(255))
    mobile = db.Column(db.String(50))
    force_change_password = db.Column(db.Integer, server_default=db.FetchedValue())
    create_date = db.Column(db.BigInteger)
    modified_date = db.Column(db.BigInteger)
    modified_by = db.Column(db.ForeignKey('users.id'), index=True)


"""
Schema tables
"""


class UserIncludePassSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = User
        include_fk = True


class UserSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = UserDisplay
        include_fk = True


class UserGroupSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Group
        include_fk = True


class SecurityPolicySchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = SecurityPolicy
        include_fk = True


class PermissionDetailSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = PermissionDetail
        include_fk = True


class ListPermissionSchema(ma.Schema):
    class Meta:
        fields = ('id', 'name', 'descriptions')


"""
init Schema
"""

list_permissions_schema = ListPermissionSchema(many=True)

user_include_pass_schema = UserIncludePassSchema()
user_schema = UserSchema()
users_schema = UserSchema(many=True)

user_group_schema = UserGroupSchema()
user_groups_schema = UserGroupSchema(many=True)

security_policy_schema = SecurityPolicySchema()
security_policies_schema = SecurityPolicySchema(many=True)

permission_schema = PermissionDetailSchema()
permissions_schema = PermissionDetailSchema(many=True)
