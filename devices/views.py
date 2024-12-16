from rest_framework import generics, status, views
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.shortcuts import get_object_or_404
from django.http import JsonResponse
from .models import Device, Payload
from .serializers import DeviceRegistrationSerializer, PayloadSerializer, PayloadListSerializer
from rest_framework.permissions import BasePermission
from rest_framework.exceptions import ValidationError
from rest_framework.authtoken.models import Token
from django.contrib.auth import authenticate


def custom_404(request, exception):
    return JsonResponse({
        'error': 'Not found',
        'status': 404,
        'message': 'The requested resource was not found'
    }, status=404)
    
class HasValidAPIKey(BasePermission):
    def has_permission(self, request, view):
        if not hasattr(request, 'auth'):
            return True
        return bool(request.auth)

class DeviceAPIKeyAuthentication(BaseAuthentication):
    def authenticate(self, request):
        api_key = request.headers.get('X-API-Key')
        if not api_key:
            raise AuthenticationFailed('No API key provided')

        try:
            device = Device.objects.get(api_key=api_key)
            return (device, api_key)
        except Device.DoesNotExist:
            raise AuthenticationFailed('Invalid API key')

    def authenticate_header(self, request):
        return 'X-API-Key'

class DeviceRegistrationView(generics.CreateAPIView):
    serializer_class = DeviceRegistrationSerializer
    permission_classes = [IsAuthenticated]

    def create(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            device = serializer.save(user=self.request.user)

            return Response({
                'dev_eui': device.dev_eui,
                'api_key': device.api_key,
            }, status=status.HTTP_201_CREATED)
        except ValidationError as e:
            return Response({
                'error': 'Validation error',
                'details': e.detail
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({
                'error': 'Internal server error',
                'details': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class PayloadCreateView(generics.CreateAPIView):
    serializer_class = PayloadSerializer
    authentication_classes = [DeviceAPIKeyAuthentication]
    permission_classes = [HasValidAPIKey]

    def create(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            
            try:
                device = Device.objects.get(
                    dev_eui=serializer.validated_data['devEUI']
                )
            except Device.DoesNotExist:
                return Response({
                    'error': 'Device not found',
                    'details': f"No device found with devEUI: {serializer.validated_data.get('devEUI')}"
                }, status=status.HTTP_404_NOT_FOUND)

            if Payload.objects.filter(
                device=device,
                f_cnt=serializer.validated_data['fCnt']
            ).exists():
                return Response({
                    'error': 'Duplicate payload',
                    'details': f"Payload with fCnt {serializer.validated_data['fCnt']} already exists for this device"
                }, status=status.HTTP_400_BAD_REQUEST)

            # Validate required fields in rxInfo and txInfo
            rx_info = serializer.validated_data.get('rxInfo', [])
            if not rx_info:
                return Response({
                    'error': 'Invalid request',
                    'details': 'rxInfo is required and must not be empty'
                }, status=status.HTTP_400_BAD_REQUEST)

            tx_info = serializer.validated_data.get('txInfo', {})
            if not tx_info:
                return Response({
                    'error': 'Invalid request',
                    'details': 'txInfo is required and must not be empty'
                }, status=status.HTTP_400_BAD_REQUEST)

            # Create payload and update device
            decoded_data = serializer.validated_data['data']
            payload_status = 'passing' if decoded_data == '01' else 'failing'

            rx_info = rx_info[0]
            
            try:
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
            except KeyError as e:
                return Response({
                    'error': 'Missing required field',
                    'details': f'Missing required field: {str(e)}'
                }, status=status.HTTP_400_BAD_REQUEST)

            device.status = payload_status
            device.save()

            return Response(
                {'message': 'Payload processed successfully',
                'status': payload_status},
                status=status.HTTP_201_CREATED
            )

        except ValidationError as e:
            return Response({
                'error': 'Validation error',
                'details': e.detail
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({
                'error': 'Internal server error',
                'details': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class DeviceStatusView(generics.RetrieveAPIView):
    permission_classes = [IsAuthenticated]  

    def get(self, request, dev_eui):
        try:
            device = Device.objects.get(dev_eui=dev_eui)
            return Response({
                'dev_eui': device.dev_eui,
                'status': device.status,
                'last_updated': device.updated_at
            })
        except Device.DoesNotExist:
            return Response({
                'error': 'Not found',
                'details': f"No device found with devEUI: {dev_eui}"
            }, status=status.HTTP_404_NOT_FOUND)
        
class DevicePayloadListView(generics.ListAPIView):
    serializer_class = PayloadListSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        device = get_object_or_404(Device, dev_eui=self.kwargs['dev_eui'])
        return Payload.objects.filter(device=device).order_by('-created_at')
    
class TokenRenewView(views.APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        """
        Renew authentication token using username and password
        """
        username = request.data.get('username')
        password = request.data.get('password')

        if not username or not password:
            return Response({
                'error': 'Please provide both username and password'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Authenticate user
        user = authenticate(username=username, password=password)

        if not user:
            return Response({
                'error': 'Invalid credentials'
            }, status=status.HTTP_401_UNAUTHORIZED)

        # Delete old token if exists
        Token.objects.filter(user=user).delete()
        
        # Create new token
        token = Token.objects.create(user=user)

        return Response({
            'token': token.key
        }, status=status.HTTP_200_OK)