"""
Services endpoints for Yggdrasil protocol
"""
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods


@csrf_exempt
@require_http_methods(["GET"])
def services(request):
    """Handle services requests"""
    return HttpResponse(
        """
        <h1>Yggdrasil Services Section</h1>
        <p>This section handles various services for Yggdrasil protocol.</p>
        <p>Available services:</p>
        <ul>
            <li>Profile services</li>
            <li>Session services</li>
            <li>Authentication services</li>
        </ul>
        """,
        content_type='text/html'
    ) 