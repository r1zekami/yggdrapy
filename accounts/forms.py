from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth import get_user_model, authenticate
User = get_user_model()
import re

class UserLoginForm(AuthenticationForm):
    username = forms.CharField(label='',
                               widget=forms.TextInput(attrs={
                                   'type': 'text',
                                   'class': 'form-control',
                                   'name': 'username',
                               }))
    password = forms.CharField(label='',
                               widget=forms.TextInput(attrs={
                                   'type': 'password',
                                   'class': 'form-control border-end-0',
                                   'name': 'password',
                                   'value':'12345678',
                                   'placeholder': 'Enter password'

                               }))

    class Meta:
        model = User
        fields = ['username', 'password']

class UserRegisterForm(UserCreationForm):
    username = forms.CharField(label='',
                               widget=forms.TextInput(attrs={
                                   'type': 'text',
                                   'class': 'form-control',
                                   'name': 'username',
                               }))
    password1 = forms.CharField(label='',
                               widget=forms.TextInput(attrs={
                                   'type': 'password',
                                   'class': 'form-control border-end-0',
                                   'name': 'password',
                                   'value':'12345678',
                                   'placeholder': 'Enter password'

                               }))

    password2 = forms.CharField(label='',
                               widget=forms.TextInput(attrs={
                                   'type': 'password',
                                   'class': 'form-control border-end-0',
                                   'name': 'password',
                                   'value':'12345678',
                                   'placeholder': 'Repeat password'

                               }))

    class Meta:
        model = User
        fields = ['username', 'password1', 'password2']

    def clean_username(self):
        username = self.cleaned_data.get('username')
        if len(username) < 3:
            raise forms.ValidationError('Your username is too short')
        if len(username) > 16:
            raise forms.ValidationError('Your username is too long')
        if not re.match(r'^[a-zA-Z0-9_-]+$', username):
            raise forms.ValidationError('Your username should contain only letters, numbers and -, _')
        if User.objects.filter(username=username).exists():
            raise forms.ValidationError('This username is already exist')
        return username



