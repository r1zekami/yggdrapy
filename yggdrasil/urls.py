"""
Yggdrasil protocol main entrypoints
"""
from django.urls import path, include
from . import views

app_name = 'yggdrasil'

urlpatterns = [
    # Main page placeholder
    path('', views.main_page, name='main'),
    
    # Auth and services root endpoints
    path('auth/', include('yggdrasil.auth.urls')),
    path('account/', include('yggdrasil.account.urls')),
    path('session/', include('yggdrasil.session.urls')),
    path('services/', include('yggdrasil.services.urls')),
    
    # Additional pattern for Minecraft client compatibility
    # Handles the duplicated session path: /yggdrasil/session/session/
    path('session/session/', include('yggdrasil.session.urls')),
] 