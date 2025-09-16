from django.urls import path
from Backend import views

urlpatterns = [
    path('',views.home, name='home'),   
    path('task/<int:task_id>/', views.view_all_items, name='view_all_items'),
    path('item/modify/', views.modify_item, name='modify_item'),
    path('item/new/', views.new_item, name='new_item'),
    path('task/new/', views.new_task, name='new_task'),  
    path('task/modify/', views.modify_task, name='modify_task'),  
]