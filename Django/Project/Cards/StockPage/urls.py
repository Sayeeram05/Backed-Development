from django.urls import path
from . import views

urlpatterns = [
    path('', views.StockPageView.as_view(), name='stock_page'),
    path('delete/', views.ModifyStockView.as_view(), name='delete_stock'),
    path('update/<int:stock_id>/', views.UpdateStockView.as_view(), name='update_stock'),
]
