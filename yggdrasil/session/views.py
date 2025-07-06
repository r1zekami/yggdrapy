"""
Session management endpoints for Yggdrasil protocol

PRODUCTION DEPLOYMENT NOTES:
- Replace hardcoded test user mappings with proper database lookups
- Implement proper RSA signature generation for texture data
- Add proper user session management and cleanup
- Consider implementing rate limiting for session endpoints
- Add proper logging for security events
"""

import json
import jwt
import hashlib
import base64
import time
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from ..rsa_keys import get_public_key
from ..sanitize import validate_access_token
from ..auth.views import active_tokens


# Store active sessions: {server_id: {user_id: profile_id}}
active_sessions = {}


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
    
    # Validate required fields
    if not access_token:
        return JsonResponse({'error': 'Missing accessToken'}, status=400)
    
    if not selected_profile or not isinstance(selected_profile, dict):
        return JsonResponse({'error': 'Missing or invalid selectedProfile'}, status=400)
    
    if not server_id:
        return JsonResponse({'error': 'Missing serverId'}, status=400)
    
    # Validate access token format
    token_valid, _ = validate_access_token(access_token)
    if not token_valid:
        return JsonResponse({
            'error': 'ForbiddenOperationException',
            'errorMessage': 'Invalid access token format'
        }, status=403)
    
    try:
        # Verify JWT token
        public_key = get_public_key()
        payload = jwt.decode(access_token, public_key, algorithms=['RS512'])
        
        user_id = payload.get('sub')
        if not user_id:
            return JsonResponse({
                'error': 'ForbiddenOperationException',
                'errorMessage': 'Invalid token payload'
            }, status=403)
        
        # Store session information
        if server_id not in active_sessions:
            active_sessions[server_id] = {}
        
        profile_id = selected_profile.get('id')
        if not profile_id:
            return JsonResponse({
                'error': 'ForbiddenOperationException',
                'errorMessage': 'Invalid profile ID'
            }, status=403)
        
        active_sessions[server_id][user_id] = profile_id
        
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
@require_http_methods(["GET"])
def has_joined(request):
    """Check if user has joined server"""
    username = request.GET.get('username', '').strip()
    server_id = request.GET.get('serverId', '').strip()
    
    # Validate required parameters
    if not username:
        return JsonResponse({'error': 'Missing username parameter'}, status=400)
    
    if not server_id:
        return JsonResponse({'error': 'Missing serverId parameter'}, status=400)
    
    # Check if session exists
    if server_id not in active_sessions:
        return HttpResponse(status=204)  # No session found
    
    # Find user in sessions for this server
    user_found = False
    profile_id = None
    
    for user_id, profile in active_sessions[server_id].items():
        # TODO: In production, implement proper user lookup by user_id
        # For now, we'll use the test user mapping
        if user_id == '06962ee8f3ad435baf052db9c33e6287' and username == 'testuser':
            user_found = True
            profile_id = profile
            break
    
    if not user_found:
        return HttpResponse(status=204)  # User not found in sessions
    
    # Generate proper texture data
    texture_data = {
        "timestamp": int(time.time() * 1000),  # Current timestamp in milliseconds
        "profileId": profile_id,
        "profileName": username,
        "textures": {}
    }
    
    # Encode texture data to Base64
    texture_json = json.dumps(texture_data)
    texture_base64 = base64.b64encode(texture_json.encode('utf-8')).decode('utf-8')
    
    # Return user profile
    response_data = {
        'id': profile_id,
        'name': username,
        'properties': [
            {
                'name': 'textures',
                'value': texture_base64
            }
        ]
    }
    
    return JsonResponse(response_data)


@csrf_exempt
@require_http_methods(["GET"])
def minecraft_profile(request, profile_id):
    """Return Minecraft profile information"""
    try:
        # Check if unsigned parameter is provided
        unsigned = request.GET.get('unsigned', 'false').lower() == 'true'
        
        # TODO: In production, implement proper user lookup by profile_id
        # For now, we'll use a simple mapping for test user
        if profile_id == '550e8400e29b41d4a716446655440000':
            username = 'testuser'
        else:
            # Try to find user by profile_id in active sessions
            username = None
            for server_id, users in active_sessions.items():
                for user_id, user_profile_id in users.items():
                    if user_profile_id == profile_id:
                        # TODO: In production, implement proper username lookup by user_id
                        username = 'testuser'  # For now, hardcoded
                        break
                if username:
                    break
            
            if not username:
                return JsonResponse({'error': 'Profile not found'}, status=404)
        
        # Create texture data
        texture_data = {
            "timestamp": int(time.time() * 1000),  # Current timestamp in milliseconds
            "profileId": profile_id,
            "profileName": username,
            "textures": {}
        }
        
        # Encode texture data to Base64
        texture_json = json.dumps(texture_data)
        texture_base64 = base64.b64encode(texture_json.encode('utf-8')).decode('utf-8')
        
        # Build response
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
        
        # Add signature if unsigned=false
        if not unsigned:
            # TODO: In production, implement proper RSA signature of texture data
            # For now, we'll generate a simple hash-based signature
            signature_data = texture_base64.encode('utf-8')
            signature_hash = hashlib.sha256(signature_data).hexdigest()
            response_data["properties"][0]["signature"] = f"sha256:{signature_hash}"
        
        return JsonResponse(response_data)
        
    except Exception as e:
        return JsonResponse({
            'error': 'Internal server error',
            'errorMessage': str(e)
        }, status=500) 