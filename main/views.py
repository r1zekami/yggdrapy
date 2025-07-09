from django.shortcuts import render, redirect
from django.contrib.auth import logout

def main_page(request):
    return render(request, 'main_page.html')

def user_logout(request):
    logout(request)
    return redirect('login')