from django.urls import path
from . import views

urlpatterns = [
    path('', views.BillingPageView.as_view(), name='billing_page')
]
