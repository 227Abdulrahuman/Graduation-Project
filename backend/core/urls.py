from django.urls import path
from core import views

urlpatterns = [
    path('', views.home_view, name='home'),
    path('webapps/', views.webapps_list, name='webapps_list'),
    path('webapps/add/', views.add_webapp_manual, name='add_webapp_manual'),
    path('targets/add/', views.target_add, name='target_add'),
    path('targets/<int:pk>/', views.target_detail, name='target_detail'),
    path('targets/<int:pk>/delete/', views.target_delete, name='target_delete'),
    path('scan/recon/', views.scan_recon, name='scan_recon'),
    path('task-status/<str:task_id>/', views.check_task_status, name='check_task_status'),
    path('targets/<int:pk>/edit/', views.target_edit, name='target_edit'),
    path('api/targets/<int:pk>/subdomains/', views.api_target_subdomains, name='api_subdomains'),
    path('api/targets/<int:pk>/webapps/', views.api_target_webapps, name='api_webapps'),
    path('scan/webapp/', views.scan_webapp, name='scan_webapp'),
    path('webapps/<int:pk>/', views.webapp_detail, name='webapp_detail'),
    path('webapps/<int:pk>/endpoints/', views.webapp_detail, name='webapp_endpoints'),
    path('webapps/<int:pk>/js-files/', views.webapp_js_files, name='webapp_js_files'),
    path('webapps/<int:pk>/archives/', views.webapp_archives, name='webapp_archives'),
    path('webapps/<int:pk>/client-routes/', views.webapp_client_routes, name='webapp_client_routes'),
    path('webapps/<int:pk>/delete/', views.webapp_delete, name='webapp_delete'),
    path('webapps/<int:pk>/js/', views.view_js_file, name='view_js_file'),
    path('webapps/<int:pk>/js-viewer/', views.js_viewer, name='js_viewer'),
    path('scan/general/', views.scan_general, name='scan_general'),
    path('task-cancel/<str:task_id>/', views.cancel_task, name='cancel_task'),
    path('api/targets/<int:pk>/vulnerabilities/', views.api_target_vulnerabilities, name='api_target_vulnerabilities'),
    path('scan/comprehensive/', views.scan_comprehensive, name='scan_comprehensive'),
    ]