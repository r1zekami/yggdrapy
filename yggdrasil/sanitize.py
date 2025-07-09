import re


def sanitize_string(value, max_length=64, allow_empty=False):
    """Sanitize string input to prevent injection attacks or something like that"""
    if not isinstance(value, str):
        return None
    
    value = re.sub(r'[\x00-\x1f\x7f]', '', value)
    value = value.strip()
    
    if len(value) > max_length:
        return None
    
    if not allow_empty and not value:
        return None
    
    return value


def validate_username(username):
    if not username:
        return False, "Username is required"
    
    sanitized = sanitize_string(username, max_length=16)
    if sanitized is None:
        return False, "Username contains invalid characters or is too long"
    
    if not re.match(r'^[a-zA-Z0-9_-]+$', sanitized):
        return False, "Username contains invalid characters"
    
    if len(sanitized) < 3:
        return False, "Username is too short (minimum 3 characters)"
    
    return True, sanitized


def validate_password(password):
    if not password:
        return False, "Password is required"
    
    sanitized = sanitize_string(password, max_length=128)
    if sanitized is None:
        return False, "Password contains invalid characters or is too long"
    
    if len(sanitized) < 6:
        return False, "Password is too short (minimum 6 characters)"
    
    return True, sanitized


def validate_client_token(client_token):
    if not client_token:
        return True, None
    
    sanitized = sanitize_string(client_token, max_length=64)
    if sanitized is None:
        return False, "Client token contains invalid characters or is too long"
    
    return True, sanitized


def validate_access_token(access_token):
    if not access_token:
        return False, "Access token is required"
    
    sanitized = sanitize_string(access_token, max_length=2048)
    if sanitized is None:
        return False, "Access token contains invalid characters or is too long"
    
    if not re.match(r'^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$', sanitized):
        return False, "Invalid access token format"
    
    return True, sanitized


def validate_json_payload(data):
    """Validate JSON payload structure and content"""
    if not isinstance(data, dict):
        return False, "Invalid JSON payload"
    
    allowed_fields = {
        'username', 'password', 'clientToken', 'requestUser',
        'accessToken', 'selectedProfile'
    }
    
    unexpected_fields = set(data.keys()) - allowed_fields
    if unexpected_fields:
        return False, f"Unexpected fields in payload: {', '.join(unexpected_fields)}"
    
    return True, "Valid payload"


def validate_credentials(username, password):
    username_valid, _ = validate_username(username)
    if not username_valid:
        return False, "Forbidden"
    
    password_valid, _ = validate_password(password)
    if not password_valid:
        return False, "Forbidden"
    
    return True, None


def sanitize_input(value):
    if isinstance(value, str):
        return sanitize_string(value, max_length=256, allow_empty=True)
    return value 
