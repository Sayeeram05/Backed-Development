from django.urls import path
from . import views

urlpatterns = [
    path('', views.UsersPageView.as_view(), name='users_page')
]
