from django.urls import path
from . import views

urlpatterns = [
    path('', views.StockPageView.as_view(), name='stock_page'),
]
