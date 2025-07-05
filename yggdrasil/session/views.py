"""
Session management endpoints for Yggdrasil protocol
"""
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods


@csrf_exempt
@require_http_methods(["GET"])
def join(request):
    """Handle server join request"""
    return HttpResponse(
        """
        <h1>Yggdrasil Session Section</h1>
        <p>This section handles session management for Yggdrasil protocol.</p>
        <p>Endpoints:</p>
        <ul>
            <li>/yggdrasil/session/join - Handle server join</li>
            <li>/yggdrasil/session/hasJoined - Check if user has joined</li>
        </ul>
        """,
        content_type='text/html'
    )


@csrf_exempt
@require_http_methods(["GET"])
def has_joined(request):
    """Check if user has joined server"""
    return HttpResponse(
        """
        <h1>Has Joined Check</h1>
        <p>This endpoint checks if a user has joined the server.</p>
        <p>Parameters:</p>
        <ul>
            <li>username - Minecraft username</li>
            <li>serverId - Server identifier</li>
        </ul>
        """,
        content_type='text/html'
    ) 