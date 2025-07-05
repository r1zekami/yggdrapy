import json
import time
import jwt
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from ..sanitize import validate_credentials, sanitize_input
from ..rsa_keys import get_private_key, get_public_key


TEST_USER = {
    'username': 'testuser',
    'password': 'testpass',
    'user_id': '06962ee8f3ad435baf052db9c33e6287',
    'profile_id': '550e8400e29b41d4a716446655440000'
}

active_tokens = {}


@csrf_exempt
@require_http_methods(["POST"])
def authenticate(request):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    client_token = data.get('clientToken', '').strip()
    
    if not client_token:
        return JsonResponse({'error': 'Missing required fields'}, status=400)
    
    credentials_valid, error_type = validate_credentials(username, password)
    if not credentials_valid:
        return JsonResponse({
            'error': 'ForbiddenOperationException',
            'errorMessage': error_type
        }, status=403)

    if username != TEST_USER['username'] or password != TEST_USER['password']:
        return JsonResponse({
            'error': 'ForbiddenOperationException',
            'errorMessage': 'Invalid credentials. Invalid username or password.'
        }, status=403)
    
    current_time = int(time.time())
    token_expiry = current_time + 86400  # 1 day
    
    jwt_payload = {
        "iss": "yggdrapy",
        "sub": TEST_USER['user_id'],
        "exp": token_expiry,
        "iat": current_time,
        "version": 0,
        "staleAt": token_expiry,
        "clientToken": client_token
    }
    
    try:
        private_key = get_private_key()
        access_token = jwt.encode(jwt_payload, private_key, algorithm='RS512')
        
        active_tokens[TEST_USER['user_id']] = access_token
        
        response_data = {
            'accessToken': access_token,
            'clientToken': client_token,
            'availableProfiles': [{
                'id': TEST_USER['profile_id'],
                'name': username
            }],
            'selectedProfile': {
                'id': TEST_USER['profile_id'],
                'name': username
            }
        }
        
        return JsonResponse(response_data)
        
    except Exception as e:
        return JsonResponse({
            'error': 'Internal server error',
            'errorMessage': str(e)
        }, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def refresh(request):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    
    access_token = data.get('accessToken', '').strip()
    client_token = data.get('clientToken', '').strip()
    
    if not access_token or not client_token:
        return JsonResponse({'error': 'Missing required fields'}, status=400)
    
    try:
        public_key = get_public_key()
        payload = jwt.decode(access_token, public_key, algorithms=['RS512'])
        
        if payload.get('clientToken') != client_token:
            return JsonResponse({
                'error': 'ForbiddenOperationException',
                'errorMessage': 'Invalid client token'
            }, status=403)
        
        user_id = payload.get('sub')
        stored_token = active_tokens.get(user_id)
        
        if not stored_token or stored_token != access_token:
            return JsonResponse({
                'error': 'ForbiddenOperationException',
                'errorMessage': 'Invalid access token'
            }, status=403)
        
        current_time = int(time.time())
        token_expiry = current_time + 86400  # 1 day
        
        new_jwt_payload = {
            'iss': 'yggdrapy',
            'sub': user_id,
            'exp': token_expiry,
            'iat': current_time,
            'version': 5,
            'staleAt': token_expiry,
            'clientToken': client_token
        }
        
        private_key = get_private_key()
        new_access_token = jwt.encode(new_jwt_payload, private_key, algorithm='RS512')
        active_tokens[user_id] = new_access_token
        
        response_data = {
            'accessToken': new_access_token,
            'clientToken': client_token
        }
        
        return JsonResponse(response_data)
        
    except jwt.ExpiredSignatureError:
        return JsonResponse({
            'error': 'ForbiddenOperationException',
            'errorMessage': 'Token expired'
        }, status=403)
    except jwt.InvalidTokenError:
        return JsonResponse({
            'error': 'ForbiddenOperationException',
            'errorMessage': 'Invalid access token'
        }, status=403)
    except Exception as e:
        return JsonResponse({
            'error': 'Internal server error',
            'errorMessage': str(e)
        }, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def validate(request):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    
    access_token = data.get('accessToken', '').strip()
    client_token = data.get('clientToken', '').strip()
    
    if not access_token:
        return JsonResponse({'error': 'Missing access token'}, status=400)
    
    try:
        public_key = get_public_key()
        payload = jwt.decode(access_token, public_key, algorithms=['RS512'])
        
        if client_token and payload.get('clientToken') != client_token:
            return JsonResponse({
                'error': 'ForbiddenOperationException',
                'errorMessage': 'Invalid client token'
            }, status=403)
        
        user_id = payload.get('sub')
        stored_token = active_tokens.get(user_id)
        
        if not stored_token or stored_token != access_token:
            return JsonResponse({
                'error': 'ForbiddenOperationException',
                'errorMessage': 'Invalid access token'
            }, status=403)
        
        return HttpResponse(status=204)
        
    except jwt.ExpiredSignatureError:
        return JsonResponse({
            'error': 'ForbiddenOperationException',
            'errorMessage': 'Token expired'
        }, status=403)
    except jwt.InvalidTokenError:
        return JsonResponse({
            'error': 'ForbiddenOperationException',
            'errorMessage': 'Invalid access token'
        }, status=403)
    except Exception as e:
        return JsonResponse({
            'error': 'Internal server error',
            'errorMessage': str(e)
        }, status=500)


@csrf_exempt
@require_http_methods(["POST"])
def signout(request):
    """Sign out user"""
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    
    if not username or not password:
        return JsonResponse({'error': 'Missing required fields'}, status=400)
    
    credentials_valid, error_type = validate_credentials(username, password)
    if not credentials_valid:
        if error_type == "Forbidden":
            return JsonResponse({
                'error': 'ForbiddenOperationException',
                'errorMessage': 'Forbidden'
            }, status=403)
        else:
            return JsonResponse({
                'error': 'ForbiddenOperationException',
                'errorMessage': 'Invalid credentials'
            }, status=403)
    
    if username != TEST_USER['username'] or password != TEST_USER['password']:
        return JsonResponse({
            'error': 'ForbiddenOperationException',
            'errorMessage': 'Invalid credentials. Invalid username or password.'
        }, status=403)
    
    return HttpResponse(status=200)


@csrf_exempt
@require_http_methods(["POST"])
def invalidate(request):
    """Invalidate access token"""
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    
    access_token = data.get('accessToken', '').strip()
    client_token = data.get('clientToken', '').strip()
    
    if not access_token or not client_token:
        return JsonResponse({'error': 'Missing required fields'}, status=400)
    
    try:
        public_key = get_public_key()
        payload = jwt.decode(access_token, public_key, algorithms=['RS512'])
        
        if payload.get('clientToken') != client_token:
            return JsonResponse({
                'error': 'ForbiddenOperationException',
                'errorMessage': 'Invalid client token'
            }, status=403)
        
        user_id = payload.get('sub')
        stored_token = active_tokens.get(user_id)
        
        if stored_token == access_token:
            del active_tokens[user_id]
        
        return HttpResponse(status=200)
        
    except jwt.InvalidTokenError:
        return JsonResponse({
            'error': 'ForbiddenOperationException',
            'errorMessage': 'Invalid access token'
        }, status=403)
    except Exception as e:
        return JsonResponse({
            'error': 'Internal server error',
            'errorMessage': str(e)
        }, status=500) 