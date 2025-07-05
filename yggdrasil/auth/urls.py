"""
URL patterns for authentication endpoints
"""
from django.urls import path
from . import views

urlpatterns = [
    path('authenticate', views.authenticate, name='authenticate'),
    path('refresh', views.refresh, name='refresh'),
    path('validate', views.validate, name='validate'),
    path('signout', views.signout, name='signout'),
    path('invalidate', views.invalidate, name='invalidate'),
] 