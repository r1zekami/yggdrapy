from django.apps import AppConfig

class ApiConfig(AppConfig):
    name = 'api'

    def ready(self):
        from api.crypto import ensure_rsa_keys_exist
        ensure_rsa_keys_exist() 