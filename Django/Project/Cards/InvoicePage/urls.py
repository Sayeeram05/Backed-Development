from django.urls import path
from . import views

urlpatterns = [
    path('', views.InvoicePageView.as_view(), name='invoice_page')
]
