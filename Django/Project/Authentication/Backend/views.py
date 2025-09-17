from django.shortcuts import render
from .forms import Login, Signup
from . import forms
# Create your views here.
def home(request):
    return render(request, 'home.html')

def login_view(request):
    form = forms.Login()
    if request.method == 'POST':
        form = forms.Login(request.POST)
        if form.is_valid():
            # Process the login (authentication logic goes here)
            print(form.cleaned_data.get('username'))
            print(form.cleaned_data.get('password'))
    return render(request, 'login.html', {'form': form})

def signup_view(request):
    form = forms.Signup()
    if request.method == 'POST':
        form = forms.Signup(request.POST)
        if form.is_valid():
            # Process the signup (user creation logic goes here)
            pass
    return render(request, 'signup.html', {'form': form})
    
