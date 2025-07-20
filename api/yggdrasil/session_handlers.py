import json
import time
import jwt
import hashlib
import base64
import re
import uuid
import os
from django.http import JsonResponse, HttpResponse, FileResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.contrib.auth.models import User
from accounts.models import Profile, Session
from api.crypto import get_public_key
from .auth_handlers import ErrorForbidden, ErrorInvalidToken


@csrf_exempt
@require_http_methods(["POST"])
def join(request):
    """
    /join
    Handle server join request. Initialize client session on minecraft server.
    Validates access token and creates session.
    
    - Client sends: accessToken, selectedProfile, serverId
    - Server validates and creates session
    - Returns: 204 No Content on success
    """
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    
    access_token = data.get('accessToken', '').strip()
    selected_profile = data.get('selectedProfile', '').strip()
    server_id = data.get('serverId', '').strip()
    
    if not access_token or not selected_profile or not server_id:
        return ErrorForbidden()
    
    # Validate serverId format (idk i mean why not)
    if not re.match(r'^[a-zA-Z0-9_-]{1,128}$', server_id):
        return ErrorForbidden()

    try:
        # Decode and verify JWT token
        public_key = get_public_key()
        payload = jwt.decode(access_token, public_key, algorithms=['RS512'])
        
        user_uuid = payload.get('sub')
        if not user_uuid:
            raise jwt.InvalidTokenError
        
        profile = Profile.objects.get(user_UUID=user_uuid, profile_UUID=selected_profile, access_token=access_token)  # type: ignore
        
        Session.objects.update_or_create(  # type: ignore
            profile=profile,
            server_id=server_id,
            defaults={"created_at": time.strftime('%Y-%m-%d %H:%M:%S')}
        )
        
        return HttpResponse(status=204)
        
    except (Profile.DoesNotExist, jwt.InvalidTokenError, jwt.ExpiredSignatureError):  # type: ignore
        return ErrorInvalidToken()
    except Exception as e:
        return JsonResponse({
            'error': 'Internal server error',
            'errorMessage': str(e)
        }, status=500)


@csrf_exempt
@require_http_methods(["GET"])
def hasJoined(request):
    """
    /hasJoined
    Check if user has joined server and tell server. Returns profile with textures if joined.
    
    - Server sends: username, serverId
    - Returns: Profile with textures (SKIN, CAPE) if session exists
    - Returns: 204 No Content if no session
    """
    username = request.GET.get('username', '').strip()
    server_id = request.GET.get('serverId', '').strip()
    
    if not username or not server_id:
        return ErrorForbidden()

    if not re.match(r'^[a-zA-Z0-9_-]{1,128}$', server_id):
        return ErrorForbidden()
    
    try:
        user = User.objects.get(username=username)
        profile = Profile.objects.get(user=user)  # type: ignore
        
        # Check if session exists
        session = Session.objects.filter(profile=profile, server_id=server_id).first()  # type: ignore
        if not session:
            return HttpResponse(status=204)
        
        # Generate texture data with SKIN and CAPE urls (Beware of trusted domain client verification, CustomSkinLoader clientmod fixes that issue)
        skin_url = "https://example.com/path/to/skin.png"
        cape_url = "https://example.com/path/to/cape.png"
        texture_data = {
            "timestamp": int(time.time() * 1000),
            "profileId": str(profile.profile_UUID),
            "profileName": username,
            "textures": {
                "SKIN": {
                    "url": skin_url,
                    "metadata": {
                        "model": "classic"
                    }
                },
                "CAPE": {
                "url": cape_url
                }
            }
        }
        
        texture_json = json.dumps(texture_data)
        texture_base64 = base64.b64encode(texture_json.encode('utf-8')).decode('utf-8')
        
        response_data = {
            'id': str(profile.profile_UUID),
            'name': username,
            'properties': [
                {
                    'name': 'textures',
                    'value': texture_base64
                }
            ]
        }
        
        return JsonResponse(response_data)
        
    except (User.DoesNotExist, Profile.DoesNotExist):  # type: ignore
        return HttpResponse(status=204)


@csrf_exempt
@require_http_methods(["GET"])
def profile(request, profile_id):
    """
    /minecraft/profile/<profile_id>
    Return Minecraft profile information with textures.
    
    - Returns: Profile with textures (SKIN, CAPE) for given profile_id
    - Supports unsigned parameter to exclude signature
    - Used by servers to get player appearance
    """
    try:
        unsigned = request.GET.get('unsigned', 'false').lower() == 'true'
        
        # Validate profile_id as UUID
        try:
            uuid_obj = uuid.UUID(profile_id)
        except (ValueError, AttributeError):
            return JsonResponse({'error': 'Profile not found'}, status=404)
        
        # Find profile in database
        try:
            profile = Profile.objects.get(profile_UUID=profile_id)  # type: ignore
            username = profile.user.username
        except Profile.DoesNotExist:  # type: ignore
            return JsonResponse({'error': 'Profile not found'}, status=404)
        
        skin_url = "https://example.com/path/to/skin.png"
        cape_url = "https://example.com/path/to/cape.png"
        texture_data = {
            "timestamp": int(time.time() * 1000),
            "profileId": str(profile_id),  # Используем параметр функции
            "profileName": username,
            "textures": {
                "SKIN": {
                    "url": skin_url,
                    "metadata": {
                        "model": "classic"
                    }
                },
                "CAPE": {
                "url": cape_url
                }
            }
        }
        
        texture_json = json.dumps(texture_data)
        texture_base64 = base64.b64encode(texture_json.encode('utf-8')).decode('utf-8')
        
        response_data = {
            "id": str(profile_id),  # without dashes
            "name": username,
            "properties": [
                {
                    "name": "textures",
                    "value": texture_base64
                }
            ]
        }
        
        return JsonResponse(response_data)
        
    except Exception as e:
        return JsonResponse({
            'error': 'Internal server error',
            'errorMessage': str(e)
        }, status=500)

