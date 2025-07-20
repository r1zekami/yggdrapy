from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from api.crypto import get_public_key

@csrf_exempt
def meta(request):
    """
    /api/authlib-injector
    Meta endpoint for authlib-injector compatibility.
    
    Returns server metadata, public keys, and skin domains.
    """
    try:
        # Get public key
        public_key = get_public_key()
        pubkey = public_key.decode('utf-8')
        
        return JsonResponse({
            "meta": {
                "implementationName": "Yggdrapy",
                "implementationVersion": "1.0.0",
                "links": {
                    "homepage": "https://127.0.0.1:8000",
                    "register": "https://127.0.0.1:8000/web/registration"
                },
                "serverName": "Yggdrapy",
                "feature.enable_profile_key": True
            },
            "signaturePublickey": pubkey,
            "signaturePublickeys": [pubkey],
            "skinDomains": ["127.0.0.1:8000", "drive.google.com"],
            "skinUrl": "https://127.0.0.1:8000/api/yggdrasil/session/test_skin"
        })
        
    except Exception as e:
        return JsonResponse({
            'error': 'Internal server error',
            'errorMessage': str(e)
        }, status=500) 