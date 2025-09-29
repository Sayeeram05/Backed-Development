from django.urls import path
from . import views

urlpatterns = [
    path('delete/', views.ModifyStockView.as_view(), name='delete_stock'),
    path('card/', views.StockPageView.as_view(), name='stock_page'),
    path('card/search/', views.SearchCardView.as_view(), name='search_card'),
    path('card/update/<int:stock_id>/', views.UpdateCardStockView.as_view(), name='update_card_stock'),
    path('bag/', views.BagsStockView.as_view(), name='bags_stock'),
    path('bag/search/', views.SearchBagView.as_view(), name='search_bag'),
    path('bag/update/<int:stock_id>/', views.UpdateBagStockView.as_view(), name='update_bag_stock'),
]
