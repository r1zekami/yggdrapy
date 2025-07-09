from django.urls import path
from .views import *

urlpatterns = [
    path('', accounts_index, name='accounts'),
    path('register/', user_register, name='register'),
    path('login/', user_login, name='login'),
]