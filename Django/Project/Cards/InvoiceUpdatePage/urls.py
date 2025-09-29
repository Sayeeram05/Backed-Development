from django.urls import path
from . import views

urlpatterns = [
    path('', views.InvoiceUpdateView.as_view(), name='invoice_update_page')
]
