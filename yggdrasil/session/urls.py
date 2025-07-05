"""
URL patterns for session endpoints
"""
from django.urls import path
from . import views

urlpatterns = [
    path('', views.join, name='session_main'),
    path('join/', views.join, name='join'),
    path('hasJoined/', views.has_joined, name='has_joined'),
] 