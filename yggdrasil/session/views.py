"""
Session management endpoints for Yggdrasil protocol
"""

import json
import jwt
import hashlib
import base64
import time
import re
import uuid
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from ..rsa_keys import get_public_key
from accounts.models import Profile, Session
from django.contrib.auth.models import User

@csrf_exempt
@require_http_methods(["GET"])
def session_main(request):
    """Main session page"""
    return HttpResponse(
        """
        <h1>Yggdrasil Session Section</h1>
        <p>This section handles session management for Yggdrasil protocol.</p>
        <p>Endpoints:</p>
        <ul>
            <li>/yggdrasil/session/join - Handle server join</li>
            <li>/yggdrasil/session/hasJoined - Check if user has joined</li>
        </ul>
        """.encode('utf-8'),
        content_type='text/html; charset=utf-8'
    )

@csrf_exempt
@require_http_methods(["POST"])
def join(request):
    """Handle server join request"""
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    access_token = data.get('accessToken', '').strip()
    selected_profile = data.get('selectedProfile', {})
    server_id = data.get('serverId', '').strip()
    client_token = data.get('clientToken', '').strip() if 'clientToken' in data else None
    if not access_token:
        return JsonResponse({'error': 'Missing accessToken'}, status=400)
    if not selected_profile or not isinstance(selected_profile, dict):
        return JsonResponse({'error': 'Missing or invalid selectedProfile'}, status=400)
    if not server_id:
        return JsonResponse({'error': 'Missing serverId'}, status=400)
    # Валидация serverId
    if not re.match(r'^[a-zA-Z0-9_-]{1,128}$', server_id):
        return JsonResponse({'error': 'Invalid serverId'}, status=400)
    # Валидация clientToken (если есть)
    if client_token:
        try:
            uuid.UUID(client_token)
        except (ValueError, AttributeError):
            return JsonResponse({'error': 'Invalid clientToken'}, status=400)
    try:
        public_key = get_public_key()
        payload = jwt.decode(access_token, public_key, algorithms=['RS512'])
        user_uuid = payload.get('sub')
        if not user_uuid:
            return JsonResponse({'error': 'ForbiddenOperationException','errorMessage': 'Invalid token payload'}, status=403)
        profile_id = selected_profile.get('id')
        if not profile_id:
            return JsonResponse({'error': 'ForbiddenOperationException','errorMessage': 'Invalid profile ID'}, status=403)
        try:
            profile = Profile.objects.get(user_UUID=user_uuid, profile_UUID=profile_id, access_token=access_token)
        except Profile.DoesNotExist:
            return JsonResponse({'error': 'ForbiddenOperationException','errorMessage': 'Invalid access token or profile'}, status=403)
        # Создаем или обновляем сессию
        Session.objects.update_or_create(
            profile=profile,
            server_id=server_id,
            defaults={"created_at": time.strftime('%Y-%m-%d %H:%M:%S')}
        )
        return HttpResponse(status=204)
    except jwt.ExpiredSignatureError:
        return JsonResponse({'error': 'ForbiddenOperationException','errorMessage': 'Token expired'}, status=403)
    except jwt.InvalidTokenError:
        return JsonResponse({'error': 'ForbiddenOperationException','errorMessage': 'Invalid access token'}, status=403)
    except Exception as e:
        return JsonResponse({'error': 'Internal server error','errorMessage': str(e)}, status=500)

@csrf_exempt
@require_http_methods(["GET"])
def has_joined(request):
    """Check if user has joined server"""
    username = request.GET.get('username', '').strip()
    server_id = request.GET.get('serverId', '').strip()
    if not username:
        return JsonResponse({'error': 'Missing username parameter'}, status=400)
    if not server_id:
        return JsonResponse({'error': 'Missing serverId parameter'}, status=400)
    # Валидация serverId
    if not re.match(r'^[a-zA-Z0-9_-]{1,128}$', server_id):
        return JsonResponse({'error': 'Invalid serverId'}, status=400)
    try:
        user = User.objects.get(username=username)
        profile = Profile.objects.get(user=user)
        session = Session.objects.filter(profile=profile, server_id=server_id).first()
        if not session:
            return HttpResponse(status=204)
        # Генерируем texture data
        texture_data = {
            "timestamp": int(time.time() * 1000),
            "profileId": str(profile.profile_UUID),
            "profileName": username,
            "textures": {}
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
    except (User.DoesNotExist, Profile.DoesNotExist):
        return HttpResponse(status=204)

@csrf_exempt
@require_http_methods(["GET"])
def minecraft_profile(request, profile_id):
    """Return Minecraft profile information"""
    try:
        unsigned = request.GET.get('unsigned', 'false').lower() == 'true'
        try:
            # Проверяем, что profile_id валидный UUID
            uuid_obj = uuid.UUID(profile_id)
        except (ValueError, AttributeError):
            return JsonResponse({'error': 'Profile not found'}, status=404)
        try:
            profile = Profile.objects.get(profile_UUID=profile_id)
            username = profile.user.username
        except Profile.DoesNotExist:
            return JsonResponse({'error': 'Profile not found'}, status=404)
        texture_data = {
            "timestamp": int(time.time() * 1000),
            "profileId": profile_id,
            "profileName": username,
            "textures": {}
        }
        texture_json = json.dumps(texture_data)
        texture_base64 = base64.b64encode(texture_json.encode('utf-8')).decode('utf-8')
        response_data = {
            "id": profile_id,
            "name": username,
            "properties": [
                {
                    "name": "textures",
                    "value": texture_base64
                }
            ]
        }
        if not unsigned:
            signature_data = texture_base64.encode('utf-8')
            signature_hash = hashlib.sha256(signature_data).hexdigest()
            response_data["properties"][0]["signature"] = f"sha256:{signature_hash}"
        return JsonResponse(response_data)
    except Exception as e:
        return JsonResponse({'error': 'Internal server error','errorMessage': str(e)}, status=500) 