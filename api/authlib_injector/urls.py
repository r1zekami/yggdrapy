from django.urls import path
from . import meta_handler
from api.yggdrasil.auth_handlers import authenticate, validate, refresh, signout, invalidate
from api.yggdrasil.session_handlers import join, hasJoined, profile

urlpatterns = [
    path('', meta_handler.meta, name='authlib_injector_meta_root'),
    path('meta', meta_handler.meta, name='authlib_injector_meta'),
    
    # Authserver endpoints
    path('authserver/authenticate', authenticate, name='authserver_authenticate'),
    path('authserver/validate', validate, name='authserver_validate'),
    path('authserver/refresh', refresh, name='authserver_refresh'),
    path('authserver/signout', signout, name='authserver_signout'),
    path('authserver/invalidate', invalidate, name='authserver_invalidate'),
    
    # Sessionserver endpoints
    path('sessionserver/minecraft/join', join, name='sessionserver_join'),
    path('sessionserver/minecraft/hasJoined', hasJoined, name='sessionserver_has_joined'),
    path('sessionserver/minecraft/profile/<str:profile_id>', profile, name='sessionserver_profile'),
    
    # Duplicated sessionserver endpoints (sessionserver/session/...)
    path('sessionserver/session/minecraft/join', join, name='sessionserver_session_join'),
    path('sessionserver/session/minecraft/hasJoined', hasJoined, name='sessionserver_session_has_joined'),
    path('sessionserver/session/minecraft/profile/<str:profile_id>', profile, name='sessionserver_session_profile'),
] 