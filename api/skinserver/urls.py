from django.urls import path
from . import skins_handler

urlpatterns = [
    path('skins/<str:username>', skins_handler.get_skin, name='get_skin'),
    path('capes/<str:username>', skins_handler.get_cape, name='get_cape'),
]
