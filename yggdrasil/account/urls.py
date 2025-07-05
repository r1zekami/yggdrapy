"""
URL patterns for account endpoints
"""
from django.urls import path
from . import views

urlpatterns = [
    path('', views.profile, name='account_main'),
    path('profile/', views.profile, name='profile'),
    path('profiles/', views.profiles, name='profiles'),
] 