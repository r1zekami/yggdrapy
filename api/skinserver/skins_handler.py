from django.http import FileResponse, HttpResponseNotFound
from django.conf import settings
import os
from pathlib import Path

def get_skin(request, username):
    skin_path = Path(settings.MEDIA_ROOT) / 'minecraft' / username / 'skins'
    
    if skin_path.exists():
        # Ищем первый PNG файл в папке skins
        for file in skin_path.glob('*.png'):
            return FileResponse(open(file, 'rb'), content_type='image/png')
    
    return HttpResponseNotFound()

def get_cape(request, username):
    cape_path = Path(settings.MEDIA_ROOT) / 'minecraft' / username / 'capes'
    
    if cape_path.exists():
        # Ищем первый PNG файл в папке capes
        for file in cape_path.glob('*.png'):
            return FileResponse(open(file, 'rb'), content_type='image/png')
    
    return HttpResponseNotFound() 