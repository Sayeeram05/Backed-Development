from django.urls import path
from . import views

urlpatterns = [
    path('', views.CardPageView.as_view(), name='card_page'),
    path('add/', views.AddCardView.as_view(), name='add_card'),
    path('modify/', views.ModifyCardView.as_view(), name='modify_card'),
    path('search/', views.SearchCardView.as_view(), name='search_card'),
]
