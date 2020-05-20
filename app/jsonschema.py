schema_user_create = {
    "type": "object",
    "properties": {
        "username": {
            "type": "string",
            "minLength": 1,
            "maxLength": 100,
            "pattern": "^[a-zA-Z0-9_.\\-\\s]+$"
        },
        "password": {
            "type": "string",
            "minLength": 1,
            "maxLength": 50
        }
    },
    "required": ["username", "password"]
}

schema_user_update = {
    "type": "object",
    "properties": {
        "firstname": {
            "type": "string",
            "minLength": 1,
            "maxLength": 100,
            "pattern": "^[a-zA-Z0-9_.\\-\\s]+$"
        },
        "lastname": {
            "type": "string",
            "minLength": 1,
            "maxLength": 100,
            "pattern": "^[a-zA-Z0-9_.\\-\\s]+$"
        }
    }
}

schema_password = {
    "type": "object",
    "properties": {
        "current_password": {
            "type": "string",
            "minLength": 1,
            "maxLength": 20
        },
        "new_password": {
            "type": "string",
            "minLength": 1,
            "maxLength": 20
        }
    },
    "required": ["new_password"]
}

schema_group = {
    "type": "object",
    "properties": {
        "name": {
            "type": "string",
            "minLength": 1,
            "maxLength": 100,
            "pattern": "^[a-zA-Z0-9_.\\-\\s]+$"
        }
    },
    "required": ["name"]
}

schema_security_policy = {
    "type": "object",
    "properties": {
        "password_min_length": {
            "type": "number",
            "minimum": 0
        },
        "login_failed_attempts": {
            "type": "number",
            "minimum": 0
        },
        "logout_after_inactivate": {
            "type": "number",
            "minimum": 0
        },
        "password_expiration": {
            "type": "number",
            "minimum": 0
        }
    }
}

schema_permission = {
    "type": "object",
    "properties": {
        "name": {
            "type": "string",
            "minLength": 1,
            "maxLength": 100,
            "pattern": "^[a-zA-Z0-9_.\\-\\s]+$"
        }
    },
    "required": ["name"]
}
