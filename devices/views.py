from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.shortcuts import get_object_or_404
from .models import Device, Payload
from .serializers import DeviceRegistrationSerializer, PayloadSerializer
from rest_framework.permissions import BasePermission

class HasValidAPIKey(BasePermission):
    def has_permission(self, request, view):
        return bool(request.auth is not None)

class DeviceAPIKeyAuthentication(BaseAuthentication):
    def authenticate(self, request):
        api_key = request.headers.get('X-API-Key')
        if not api_key:
            return None

        try:
            device = Device.objects.get(api_key=api_key)
            return (device, api_key)
        except Device.DoesNotExist:
            raise AuthenticationFailed('Invalid API key')

class DeviceRegistrationView(generics.CreateAPIView):
    serializer_class = DeviceRegistrationSerializer
    permission_classes = [IsAuthenticated]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        device = serializer.save(user=self.request.user)

        return Response({
            'dev_eui': device.dev_eui,
            'api_key': device.api_key,
        }, status=status.HTTP_201_CREATED)

class PayloadCreateView(generics.CreateAPIView):
    serializer_class = PayloadSerializer
    authentication_classes = [DeviceAPIKeyAuthentication]
    permission_classes = [HasValidAPIKey] 

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        device = Device.objects.get(
            dev_eui=serializer.validated_data['devEUI']
        )

        if Payload.objects.filter(
            device=device,
            f_cnt=serializer.validated_data['fCnt']
        ).exists():
            return Response(
                {"error": "Duplicate payload"},
                status=status.HTTP_400_BAD_REQUEST
            )

        decoded_data = serializer.validated_data['data']
        payload_status = 'passing' if decoded_data == '01' else 'failing'

        rx_info = serializer.validated_data['rxInfo'][0]
        tx_info = serializer.validated_data['txInfo']
        
        payload = Payload.objects.create(
            device=device,
            f_cnt=serializer.validated_data['fCnt'],
            data=serializer.validated_data['data'],
            decoded_data=decoded_data,
            status=payload_status,
            gateway_id=rx_info['gatewayID'],
            gateway_name=rx_info['name'],
            gateway_time=rx_info['time'],
            rssi=rx_info['rssi'],
            lora_snr=rx_info['loRaSNR'],
            frequency=tx_info['frequency'],
            dr=tx_info['dr']
        )

        device.status = payload_status
        device.save()

        return Response(
            {"message": "Payload processed successfully"},
            status=status.HTTP_201_CREATED
        )

class DevicePayloadListView(generics.ListAPIView):
    serializer_class = PayloadSerializer
    authentication_classes = [DeviceAPIKeyAuthentication]
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        device = get_object_or_404(Device, dev_eui=self.kwargs['dev_eui'])
        return Payload.objects.filter(device=device).order_by('-created_at')