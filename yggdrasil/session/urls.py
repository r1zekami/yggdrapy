"""
URL patterns for session endpoints
"""
from django.urls import path
from . import views

urlpatterns = [
    path('join', views.join, name='join'),
    path('join/', views.join, name='join_slash'),
    path('hasJoined', views.has_joined, name='has_joined'),
    path('hasJoined/', views.has_joined, name='has_joined_slash'),
    path('minecraft/profile/<str:profile_id>', views.minecraft_profile, name='minecraft_profile'),
    path('minecraft/profile/<str:profile_id>/', views.minecraft_profile, name='minecraft_profile_slash'),
] 

