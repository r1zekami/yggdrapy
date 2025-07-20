"""
URL patterns for authentication endpoints
"""
from django.urls import path, include
from . import auth_handlers, session_handlers, services_handlers

urlpatterns = [
    path('auth/', include([
        path('authenticate', auth_handlers.authenticate, name='authenticate'),
        path('validate', auth_handlers.validate, name='validate'),
        path('refresh', auth_handlers.refresh, name='refresh'),
        path('signout', auth_handlers.signout, name='signout'),
        path('invalidate', auth_handlers.invalidate, name='invalidate'),
    ])),
    path('session/', include([
        path('minecraft/join', session_handlers.join, name='join'),
        path('minecraft/hasJoined', session_handlers.hasJoined, name='has_joined'),
        path('minecraft/profile/<str:profile_id>', session_handlers.profile, name='minecraft_profile'),
        
        # Not only /session/minecraft/* should be used, but also /session/session/minecraft/*
        # For some reason, to properly work, session endpoints need to be duplicated like that
        path('session/', include([
            path('minecraft/join', session_handlers.join, name='join'),
            path('minecraft/hasJoined', session_handlers.hasJoined, name='has_joined'),
            path('minecraft/profile/<str:profile_id>', session_handlers.profile, name='minecraft_profile')
        ]))
    ])),
    path('services/', include([
        path('publickeys', services_handlers.publickeys, name='publickeys'),
        path('publickeys/', services_handlers.publickeys, name='publickeys'),
    ])),
]


