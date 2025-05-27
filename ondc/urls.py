from django.urls import path
from .views import ondc_site_verification, on_subscribe

urlpatterns = [
    path('on_subscribe', on_subscribe, name='on_subscribe')    
]
