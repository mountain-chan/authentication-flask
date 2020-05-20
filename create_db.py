from app.app import create_app
from app.extensions import db
from app.models import PermissionDetail, Group, User, SecurityPolicy
from app.settings import DevConfig

app = create_app(config_object=DevConfig)
app_context = app.app_context()
app_context.push()
db.create_all()
PermissionDetail.insert_permissions()
Group.insert_groups()
User.insert_user()
SecurityPolicy.insert_policy()
