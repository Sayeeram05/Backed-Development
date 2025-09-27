from django.urls import path
from . import views

urlpatterns = [
    path('', views.CardPageView.as_view(), name='card_page'),
    path('add/', views.AddCardView.as_view(), name='add_card'),
    path('update/', views.UpdateCardView.as_view(), name='update_card'),
    path('search/', views.SearchCardView.as_view(), name='search_card'),
    path('delete/<str:card_code>/', views.DeleteCardView.as_view(), name='delete_card'),
]
