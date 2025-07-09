"""
URL patterns for authentication endpoints
"""
from django.urls import path
from . import views

urlpatterns = [
    path('authenticate', views.authenticate, name='authenticate'),
    path('authenticate/', views.authenticate, name='authenticate_slash'),
    path('refresh', views.refresh, name='refresh'),
    path('refresh/', views.refresh, name='refresh_slash'),
    path('validate', views.validate, name='validate'),
    path('validate/', views.validate, name='validate_slash'),
    path('signout', views.signout, name='signout'),
    path('signout/', views.signout, name='signout_slash'),
    path('invalidate', views.invalidate, name='invalidate'),
    path('invalidate/', views.invalidate, name='invalidate_slash'),
] 