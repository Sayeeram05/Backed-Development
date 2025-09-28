from django.urls import path
from . import views

urlpatterns = [
    path('', views.StockPageView.as_view(), name='stock_page'),
    path('delete/', views.ModifyStockView.as_view(), name='delete_stock'),
    path('card/update/<int:stock_id>/', views.UpdateCardStockView.as_view(), name='update_card_stock'),
    path('bag/update/<int:stock_id>/', views.UpdateBagStockView.as_view(), name='update_bag_stock'),
]
