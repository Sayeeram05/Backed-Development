from django.shortcuts import redirect, render
from django.contrib.auth.hashers import make_password, check_password
from . import forms
from .models import User

# Create your views here.
def home(request):
    return render(request, 'home.html')

def login_view(request):
    form = forms.Login()
    if request.method == 'POST':
        form = forms.Login(request.POST)
        print(form.is_valid())
        print(form.errors) 
        print(form.cleaned_data)  # Debugging line to see cleaned data
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            try:
                user = User.objects.get(username=username)
                if user and check_password(password, user.password):
                    return redirect('home')
                else:
                    # Add error to form instead of printing
                    form.add_error(None, "Invalid username or password.")
            except User.DoesNotExist:
                # Add error to form instead of printing
                form.add_error(None, "Invalid username or password.")
    return render(request, 'login.html', {'form': form})

def signup_view(request):
    form = forms.Signup()
    if request.method == 'POST':
        form = forms.Signup(request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            email = form.cleaned_data.get('email')
            has_error = False
            
            if User.objects.filter(username=username).exists():
                # Add error to form instead of printing
                form.add_error('username', "Username already exists.")
                has_error = True
                
            if User.objects.filter(email=email).exists():
                # Add error to form instead of printing
                form.add_error('email', "Email already exists.")
                has_error = True
                
            if not has_error:
                newUser = User(username=username, email=email, password=make_password(password))
                newUser.save()
                return redirect("login")
    return render(request, 'signup.html', {'form': form})

