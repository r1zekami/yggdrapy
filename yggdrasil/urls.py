"""
URL configuration for Yggdrasil protocol
"""
from django.urls import path, include
from . import views

app_name = 'yggdrasil'

urlpatterns = [
    path('', views.main_page, name='main'),
    
    # Include modular endpoints
    path('auth/', include('yggdrasil.auth.urls')),
    path('account/', include('yggdrasil.account.urls')),
    path('session/', include('yggdrasil.session.urls')),
    path('services/', include('yggdrasil.services.urls')),
] 