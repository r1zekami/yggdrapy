import json
import time
import jwt
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.contrib.auth import authenticate as dj_authenticate
from accounts.models import Profile
from django.contrib.auth.models import User
import uuid
from ..rsa_keys import get_private_key, get_public_key

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
    if not username or not password:
        return JsonResponse({'error': 'Missing required fields'}, status=400)
    # Username validation (Yggdrasil: 3-16 chars, a-zA-Z0-9_-)
    import re
    if not re.match(r'^[a-zA-Z0-9_-]{3,16}$', username):
        return JsonResponse({
            'error': 'ForbiddenOperationException',
            'errorMessage': 'Forbidden'
        }, status=403)
    if len(password) > 100 or '\n' in password or '\t' in password:
        return JsonResponse({
            'error': 'ForbiddenOperationException',
            'errorMessage': 'Forbidden'
        }, status=403)
    user = dj_authenticate(username=username, password=password)
    if not user:
        return JsonResponse({
            'error': 'ForbiddenOperationException',
            'errorMessage': 'Invalid credentials. Invalid username or password.'
        }, status=403)
    try:
        profile = Profile.objects.get(user=user)
    except Profile.DoesNotExist:
        return JsonResponse({'error': 'Profile not found'}, status=404)
    # Определяем clientToken
    if client_token:
        profile.client_token = client_token
    else:
        if profile.client_token:
            client_token = profile.client_token
        else:
            import uuid
            client_token = str(uuid.uuid4())
            profile.client_token = client_token
    # Генерируем accessToken
    current_time = int(time.time())
    token_expiry = current_time + 86400
    jwt_payload = {
        "iss": "yggdrapy",
        "sub": str(profile.user_UUID),
        "exp": token_expiry,
        "iat": current_time,
        "version": 0,
        "staleAt": token_expiry,
        "clientToken": client_token
    }
    private_key = get_private_key()
    access_token = jwt.encode(jwt_payload, private_key, algorithm='RS512')
    profile.access_token = access_token
    profile.save()
    response_data = {
        'accessToken': access_token,
        'clientToken': client_token,
        'availableProfiles': [{
            'id': str(profile.profile_UUID),
            'name': user.username
        }],
        'selectedProfile': {
            'id': str(profile.profile_UUID),
            'name': user.username
        }
    }
    return JsonResponse(response_data)

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
        user_uuid = payload.get('sub')
        if not user_uuid:
            raise jwt.InvalidTokenError
        profile = Profile.objects.get(user_UUID=user_uuid)
        if profile.access_token != access_token or profile.client_token != client_token:
            return JsonResponse({
                'error': 'ForbiddenOperationException',
                'errorMessage': 'Invalid access token or client token'
            }, status=403)
        # Проверяем не истёк ли токен
        if payload.get('exp', 0) < int(time.time()):
            return JsonResponse({
                'error': 'ForbiddenOperationException',
                'errorMessage': 'Token expired'
            }, status=403)
        # Генерируем новый accessToken
        current_time = int(time.time())
        token_expiry = current_time + 86400
        new_jwt_payload = {
            'iss': 'yggdrapy',
            'sub': str(profile.user_UUID),
            'exp': token_expiry,
            'iat': current_time,
            'version': 5,
            'staleAt': token_expiry,
            'clientToken': client_token
        }
        private_key = get_private_key()
        new_access_token = jwt.encode(new_jwt_payload, private_key, algorithm='RS512')
        profile.access_token = new_access_token
        profile.save()
        response_data = {
            'accessToken': new_access_token,
            'clientToken': client_token,
            'selectedProfile': {
                'id': str(profile.profile_UUID),
                'name': profile.user.username
            }
        }
        return JsonResponse(response_data)
    except (Profile.DoesNotExist, jwt.InvalidTokenError, jwt.ExpiredSignatureError):
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
        user_uuid = payload.get('sub')
        if not user_uuid:
            raise jwt.InvalidTokenError
        profile = Profile.objects.get(user_UUID=user_uuid)
        if profile.access_token != access_token:
            return JsonResponse({
                'error': 'ForbiddenOperationException',
                'errorMessage': 'Invalid access token'
            }, status=403)
        if client_token and profile.client_token != client_token:
            return JsonResponse({
                'error': 'ForbiddenOperationException',
                'errorMessage': 'Invalid client token'
            }, status=403)
        # Проверяем не истёк ли токен
        if payload.get('exp', 0) < int(time.time()):
            return JsonResponse({
                'error': 'ForbiddenOperationException',
                'errorMessage': 'Token expired'
            }, status=403)
        return HttpResponse(status=204)
    except (Profile.DoesNotExist, jwt.InvalidTokenError, jwt.ExpiredSignatureError):
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
def invalidate(request):
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
        user_uuid = payload.get('sub')
        if not user_uuid:
            raise jwt.InvalidTokenError
        profile = Profile.objects.get(user_UUID=user_uuid, access_token=access_token, client_token=client_token)
        profile.access_token = None
        profile.save()
        return HttpResponse(status=200)
    except (Profile.DoesNotExist, jwt.InvalidTokenError):
        return JsonResponse({'error': 'ForbiddenOperationException', 'errorMessage': 'Invalid access token'}, status=403)
    except Exception as e:
        return JsonResponse({'error': 'Internal server error', 'errorMessage': str(e)}, status=500)

@csrf_exempt
@require_http_methods(["POST"])
def signout(request):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    if not username or not password:
        return JsonResponse({'error': 'Missing required fields'}, status=400)
    user = dj_authenticate(username=username, password=password)
    if not user:
        return JsonResponse({
            'error': 'ForbiddenOperationException',
            'errorMessage': 'Invalid credentials. Invalid username or password.'
        }, status=403)
    try:
        profile = Profile.objects.get(user=user)
        profile.access_token = None
        profile.save()
    except Profile.DoesNotExist:
        pass
    return HttpResponse(status=200) 