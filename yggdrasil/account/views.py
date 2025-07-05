"""
Account management endpoints for Yggdrasil protocol
"""
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods


@csrf_exempt
@require_http_methods(["GET"])
def profile(request):
    """Handle profile requests"""
    return HttpResponse(
        """
        <h1>Yggdrasil Account Section</h1>
        <p>This section handles account management for Yggdrasil protocol.</p>
        <p>Endpoints:</p>
        <ul>
            <li>/yggdrasil/account/profile - Get user profile</li>
            <li>/yggdrasil/account/profiles - Get multiple profiles</li>
        </ul>
        """,
        content_type='text/html'
    )


@csrf_exempt
@require_http_methods(["GET"])
def profiles(request):
    """Handle multiple profiles request"""
    return HttpResponse(
        """
        <h1>Multiple Profiles</h1>
        <p>This endpoint returns multiple user profiles.</p>
        <p>Parameters:</p>
        <ul>
            <li>usernames - Comma-separated list of usernames</li>
        </ul>
        """,
        content_type='text/html'
    ) 