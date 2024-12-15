from django.urls import path
from .views import DeviceRegistrationView, PayloadCreateView, DevicePayloadListView

urlpatterns = [
    path('register/', DeviceRegistrationView.as_view(), name='device-register'),
    path('payload/', PayloadCreateView.as_view(), name='create-payload'),
    path('device/<str:dev_eui>/payloads/', DevicePayloadListView.as_view(), name='device-payloads'),
]