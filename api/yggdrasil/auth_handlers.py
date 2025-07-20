import json
import time
import jwt
import re
import uuid
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.contrib.auth import authenticate as dj_authenticate
from accounts.models import Profile
from api.crypto import get_private_key, get_public_key, generate_access_token


'''Error specification is like https://minecraft.wiki/w/Yggdrasil#Joining_a_Server but simplified'''
# An attempt to sign in using empty or insufficiently short credentials.
def ErrorForbidden():
    return JsonResponse({'error': 'ForbiddenOperationException', 'errorMessage': 'Forbidden'}, status=403)

#Either a successful attempt to sign in using an account with excessive login attempts or an unsuccessful attempt to sign in using a non-existent account.
def ErrorInvalidCredentials():
    return JsonResponse({'error': 'ForbiddenOperationException',
    'errorMessage': 'Invalid credentials. Invalid username or password.'}, status=403)

#An attempt to validate an access token obtained from the /authenticate endpoint that has expired or become invalid.
def ErrorInvalidToken():
    return JsonResponse({'error': 'ForbiddenOperationException','errorMessage': 'Invalid token'}, status=400)


'''Authentification handlers: /authenticate /refresh /validate /signout /invalidate'''

@csrf_exempt
@require_http_methods(["POST"])
def authenticate(request):
    """
    /authenticate
    Handle authentication request, authenticates a user using their password.
    Checks for login password and generate Access Token (Client Token if is not specified)
    """

    # Validate JSON
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=403)
    
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    client_token = data.get('clientToken', '').strip()
    # RequestUser is ignored
    
    if not username or not password:
        return JsonResponse({'error': 'Missing required fields'}, status=403)
    
    # Validate clientToken length if provided (max 36 for UUID with dashes)
    if client_token and (len(client_token) < 10 or len(client_token) > 36):
        return JsonResponse({'error': 'Invalid Client Token format'}, status=403)
    
    # Some sanitization (based on minecraft nickname format)
    # if not re.match(r'^[a-zA-Z0-9_-]{3,16}$', username):
    #     return ErrorForbidden()
    # if len(password) > 100 or '\n' in password or '\t' in password:
    #     return ErrorForbidden()
    
    # Django Authenticate from database
    user = dj_authenticate(username=username, password=password)
    if not user:
        return ErrorInvalidCredentials()

    try:
        profile = Profile.objects.get(user=user)  # type: ignore
    except Profile.DoesNotExist:  # type: ignore
        return ErrorInvalidCredentials()
    

    # Load given Client Token, use existing if not specified
    # Generate new if there is none in database and it's not specified
    if client_token:
        profile.client_token = client_token
    else:
        if profile.client_token:
            client_token = profile.client_token
        else:
            client_token = uuid.uuid4().hex
            profile.client_token = client_token
    

    access_token = generate_access_token(profile, client_token)
    profile.access_token = access_token
    profile.save()
    
    response_data = {
        'accessToken': access_token,
        'clientToken': client_token,
        'availableProfiles': [{
            'id': profile.profile_UUID,
            'name': user.username
        }],
        'selectedProfile': {
            'id': profile.profile_UUID,
            'name': user.username
        }
    }
    
    return JsonResponse(response_data)


@csrf_exempt
@require_http_methods(["POST"])
def refresh(request):
    """
    /refresh
    Refresh an Access Token using a valid Access Token and a Client Token
    The provided accessToken gets invalidated (In our case - deleted from database)
    """

    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return ErrorForbidden()
    
    access_token = data.get('accessToken', '').strip()
    client_token = data.get('clientToken', '').strip()
    
    if not access_token or not client_token:
        return ErrorInvalidToken()
    
    # Validate clientToken length (max 36 for UUID with dashes)
    if len(client_token) < 1 or len(client_token) > 36:
        return ErrorForbidden()
    
    try:
        # Decode and verify JWT token, compare it with token from db, check for expiration, generate new one
        public_key = get_public_key()
        payload = jwt.decode(access_token, public_key, algorithms=['RS512'])
        
        user_uuid = payload.get('sub')
        if not user_uuid:
            raise jwt.InvalidTokenError
        
        profile = Profile.objects.get(user_UUID=user_uuid)  # type: ignore
        
        if profile.access_token != access_token or profile.client_token != client_token:
            return ErrorInvalidToken()
        
        current_time = int(time.time())
        if payload.get('exp', 0) < current_time:
            return ErrorInvalidToken()
        
        new_access_token = generate_access_token(profile, client_token)
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
        
    except jwt.InvalidTokenError:
        return ErrorInvalidToken()
    except Profile.DoesNotExist:  # type: ignore
        return ErrorInvalidToken()


@csrf_exempt
@require_http_methods(["POST"])
def validate(request):
    """
    /validate
    Validate an access token. Checks if an accessToken is usable for authentication with a Minecraft server. 
    The Minecraft Launcher calls this endpoint on startup to verify that it's saved token is still usable, 
    and calls /refresh if this returns an error.
    """
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return ErrorForbidden()
    
    access_token = data.get('accessToken', '').strip()
    client_token = data.get('clientToken', '').strip()
    
    if not access_token:
        return ErrorInvalidToken()
    
    # Validate clientToken length if provided (max 36 for UUID with dashes)
    if client_token and (len(client_token) < 1 or len(client_token) > 36):
        return ErrorForbidden()
    
    try:
        # Decode and verify JWT Access Token, compare it with token from db, verify it matches, check expiration date, return 204 if valid
        public_key = get_public_key()
        payload = jwt.decode(access_token, public_key, algorithms=['RS512'])
        
        user_uuid = payload.get('sub')
        if not user_uuid:
            raise jwt.InvalidTokenError
        
        profile = Profile.objects.get(user_UUID=user_uuid)  # type: ignore
        
        if profile.access_token != access_token:
            return ErrorInvalidToken()
        
        if client_token and profile.client_token != client_token:
            return ErrorInvalidToken()
        
        current_time = int(time.time())
        if payload.get('exp', 0) < current_time:
            return ErrorInvalidToken()
        
        # Valid Token, 204 no content
        return JsonResponse({}, status=204)
        
    except (Profile.DoesNotExist, jwt.InvalidTokenError):  # type: ignore
        return ErrorInvalidToken()


@csrf_exempt
@require_http_methods(["POST"])
def signout(request):
    """
    /signout
    Sign out using username and password. Invalidates all access tokens for the user.
    """
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return ErrorForbidden()
    
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    
    if not username or not password:
        return ErrorInvalidCredentials()
    
    # Django Authenticate from database
    user = dj_authenticate(username=username, password=password)
    if not user:
        return ErrorInvalidCredentials()
    
    try:
        profile = Profile.objects.get(user=user)  # type: ignore
        profile.access_token = None
        profile.save()
    except Profile.DoesNotExist:  # type: ignore
        pass  # User doesn't have profile, but signout is still successful. It's some sort of unrealistic scenario
              # but it better be here just for UB avoiding
    
    #204 No Content
    return JsonResponse({}, status=204)


@csrf_exempt
@require_http_methods(["POST"])
def invalidate(request):
    """
    /invalidate
    Invalidate access token using client token. Invalidates the access token used in the request.
    """
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return ErrorForbidden()
    
    access_token = data.get('accessToken', '').strip()
    client_token = data.get('clientToken', '').strip()
    
    if not access_token or not client_token:
        return ErrorInvalidToken()
    
    # Validate clientToken length (max 36 for UUID with dashes)
    if len(client_token) < 1 or len(client_token) > 36:
        return ErrorForbidden()
    
    try:
        # Decode and verify JWT token, compare it with token from db, invalidate if valid
        public_key = get_public_key()
        payload = jwt.decode(access_token, public_key, algorithms=['RS512'])
        
        user_uuid = payload.get('sub')
        if not user_uuid:
            raise jwt.InvalidTokenError
        
        profile = Profile.objects.get(user_UUID=user_uuid, access_token=access_token, client_token=client_token)  # type: ignore
        profile.access_token = None
        profile.save()
        
        # 204 No Content
        return JsonResponse({}, status=204)
        
    except jwt.InvalidTokenError:
        return ErrorInvalidToken()
    except Profile.DoesNotExist:  # type: ignore
        return ErrorInvalidToken()
