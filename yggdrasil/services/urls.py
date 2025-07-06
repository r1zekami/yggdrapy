"""
URL patterns for services endpoints
"""
from django.urls import path
from . import views

urlpatterns = [
    path('', views.services, name='services'),
    path('publickeys', views.publickeys, name='publickeys'),
] 