from django.urls import path
from . import views

urlpatterns = [
    path('on_subscribe', views.on_subscribe, name='on_subscribe'),
    path('ondc-site-verification.html', views.verify_html, name='verify_html'),
    path('', views.health_check, name='health_check'),   
]