from django.urls import path
from .views import *

urlpatterns = [
    path('', main_page, name='main'),
    path('logout/', user_logout, name='logout'),
]