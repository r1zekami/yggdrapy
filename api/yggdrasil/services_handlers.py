import json
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from api.crypto import get_public_key


@csrf_exempt
@require_http_methods(["GET"])
def publickeys(request):
    """
    /services/publickeys
    Return server metadata and public keys
    """
    try:
        public_key = get_public_key()
        pem_content = public_key.decode('utf-8')
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
