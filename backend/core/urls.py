from django.urls import path
from core import views

urlpatterns = [
    path('', views.home_view, name='home'),
    path('targets/add/', views.target_add, name='target_add'),
    path('targets/<int:pk>/', views.target_detail, name='target_detail'),
    path('targets/<int:pk>/delete/', views.target_delete, name='target_delete'),
    path('scan/recon/', views.scan_recon, name='scan_recon'),
    path('task-status/<str:task_id>/', views.check_task_status, name='check_task_status'),
    path('targets/<int:pk>/edit/', views.target_edit, name='target_edit'),
    ]