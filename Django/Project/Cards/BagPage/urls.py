from django.urls import path
from . import views

urlpatterns = [
    path('', views.BagPageView.as_view(), name='bag_page'),
    path('add/', views.AddBagView.as_view(), name='add_bag'),
    path('update/', views.UpdateBagView.as_view(), name='update_bag'),
    path('search/', views.SearchBagView.as_view(), name='search_bag'),
    path('delete/<str:bag_code>/', views.DeleteBagView.as_view(), name='delete_bag'),
]
