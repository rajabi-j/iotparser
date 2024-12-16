from rest_framework import serializers
from .models import Device, Payload
from django.core.validators import RegexValidator
import base64

class DeviceRegistrationSerializer(serializers.ModelSerializer):
    dev_eui = serializers.CharField(
        max_length=16,
        validators=[
            RegexValidator(
                regex='^[0-9A-Fa-f]{16}$',
                message='DevEUI must be a 16-character hexadecimal string'
            )
        ]
    )

    class Meta:
        model = Device
        fields = ['dev_eui', 'user']
        read_only_fields = ['api_key']

    def validate_dev_eui(self, value):
        if Device.objects.filter(dev_eui=value).exists():
            raise serializers.ValidationError("Device with this DevEUI already exists")
        return value.upper()

class PayloadSerializer(serializers.Serializer):
    fCnt = serializers.IntegerField(min_value=0)
    devEUI = serializers.CharField(
        max_length=16,
        validators=[
            RegexValidator(
                regex='^[0-9A-Fa-f]{16}$',
                message='DevEUI must be a 16-character hexadecimal string'
            )
        ]
    )
    data = serializers.CharField()
    rxInfo = serializers.ListField(
        child=serializers.DictField(
            required=True
        ),
        min_length=1
    )
    txInfo = serializers.DictField()

    def validate_data(self, value):
        try:
            decoded = base64.b64decode(value).hex()
            return decoded
        except Exception as e:
            raise serializers.ValidationError("Invalid base64 data")

    def validate_rxInfo(self, value):
        required_fields = ['gatewayID', 'name', 'time', 'rssi', 'loRaSNR']
        if not value:
            raise serializers.ValidationError("rxInfo must not be empty")
        
        for field in required_fields:
            if field not in value[0]:
                raise serializers.ValidationError(f"Missing required field: {field}")
        return value

    def validate_txInfo(self, value):
        required_fields = ['frequency', 'dr']
        for field in required_fields:
            if field not in value:
                raise serializers.ValidationError(f"Missing required field: {field}")
        return value
    
class PayloadListSerializer(serializers.ModelSerializer):
    class Meta:
        model = Payload
        fields = ['f_cnt', 'data', 'decoded_data', 'status', 'gateway_id', 
                 'gateway_name', 'gateway_time', 'rssi', 'lora_snr', 
                 'frequency', 'dr', 'created_at']