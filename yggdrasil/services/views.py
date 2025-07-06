"""
Services endpoints for Yggdrasil protocol
"""
import json
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from ..rsa_keys import get_public_key


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
        """.encode('utf-8'),
        content_type='text/html; charset=utf-8'
    )


@csrf_exempt
@require_http_methods(["GET"])
def publickeys(request):
    """Return public keys for profile property verification"""
    try:
        # Get our public key for texture verification
        public_key = get_public_key()
        
        # Convert PEM to Base64 (remove headers and newlines)
        pem_content = public_key.decode('utf-8')
        # Remove BEGIN/END headers and newlines
        base64_key = pem_content.replace('-----BEGIN PUBLIC KEY-----', '').replace('-----END PUBLIC KEY-----', '').replace('\n', '')
        
        response_data = {
            "playerCertificateKeys": [
                {
                    "publicKey": base64_key
                }
            ],
            "profilePropertyKeys": [
                {
                    "publicKey": base64_key
                }
            ]
        }
        
        return JsonResponse(response_data)
        
    except Exception as e:
        return JsonResponse({
            'error': 'Internal server error',
            'errorMessage': str(e)
        }, status=500) 