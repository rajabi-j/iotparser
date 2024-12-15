from rest_framework import serializers
from .models import Device, Payload
import base64

class DeviceRegistrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Device
        fields = ['dev_eui', 'user']
        read_only_fields = ['api_key']
        
    def create(self, validated_data):
        device = Device.objects.create(**validated_data)
        return device

class PayloadSerializer(serializers.Serializer):
    fCnt = serializers.IntegerField()
    devEUI = serializers.CharField()
    data = serializers.CharField()
    rxInfo = serializers.ListField()
    txInfo = serializers.DictField()

    def validate_data(self, value):
        try:
            decoded = base64.b64decode(value).hex()
            return decoded
        except Exception as e:
            raise serializers.ValidationError("Invalid base64 data")