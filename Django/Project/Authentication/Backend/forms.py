from django import forms
from .models import User

class Signup(forms.ModelForm):
    class Meta:
        model = User
        fields = ['username', 'email', 'password']
        widgets = {
            'password': forms.PasswordInput(),
        }

class Login(forms.Form):
    # Regular Form that doesn't check model constraints
    username = forms.CharField(max_length=150)
    password = forms.CharField(widget=forms.PasswordInput())