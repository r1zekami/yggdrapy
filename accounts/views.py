from django.shortcuts import render, redirect
from .forms import UserRegisterForm, UserLoginForm
from django.contrib.auth import authenticate, login, logout

from .models import Profile

def accounts_index(request):
    if request.user.is_authenticated:
        return redirect('main')
    else:
        return redirect('login')

def user_register(request):
    if request.user.is_authenticated:
        return redirect('main')
    else:
        if request.method == 'POST':
            form = UserRegisterForm(request.POST)
            if form.is_valid():
                user = form.save()
                Profile.objects.create(user=user)
                login(request, user)
                return redirect('main')
        else:
            form = UserRegisterForm()
        return render(request, 'register.html', {'form': form})

def user_login(request):
    if request.user.is_authenticated:
        return redirect('main')
    else:
        if request.method == 'POST':
            form = UserLoginForm(data=request.POST)
            if form.is_valid():
                user = form.get_user()
                login(request, user)
                return redirect('main')
        else:
            form = UserLoginForm()
        return render(request, 'login.html', {"form": form})



