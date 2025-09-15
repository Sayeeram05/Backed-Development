from django.urls import path
from .views import login_view, signup_view
from Frontend.views import home

urlpatterns = [
    path('login/', login_view, name='login'), 
    path('signup/', signup_view, name='signup'),
    path('', home, name='home'),  
]