from django.db import models
from django.contrib.auth.models import User
import secrets

class Device(models.Model):
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='devices')
    dev_eui = models.CharField(max_length=16, unique=True)
    status = models.CharField(
        max_length=7,
        choices=[('passing', 'Passing'), ('failing', 'Failing')],
        default='failing'
    )
    api_key = models.CharField(max_length=100, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Device {self.dev_eui} - {self.status}"

    def save(self, *args, **kwargs):
        if not self.api_key:
            self.api_key = secrets.token_urlsafe(32)
        super().save(*args, **kwargs)

class Payload(models.Model):
    device = models.ForeignKey(Device, on_delete=models.CASCADE, related_name='payloads')
    f_cnt = models.IntegerField()
    data = models.CharField(max_length=255)
    decoded_data = models.CharField(max_length=255)
    status = models.CharField(
        max_length=7,
        choices=[('passing', 'Passing'), ('failing', 'Failing')]
    )
    gateway_id = models.CharField(max_length=16)
    gateway_name = models.CharField(max_length=255)
    gateway_time = models.DateTimeField()
    rssi = models.IntegerField()
    lora_snr = models.FloatField()
    frequency = models.IntegerField()
    dr = models.IntegerField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ['device', 'f_cnt']
