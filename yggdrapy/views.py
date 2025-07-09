from django.shortcuts import redirect


def index(request):
    if request.user.is_authenticated:
        return redirect('main')
    else:
        return redirect('login')