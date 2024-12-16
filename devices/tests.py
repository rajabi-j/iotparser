from django.urls import reverse
from rest_framework.test import APITestCase
from rest_framework import status
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token
from .models import Device
from datetime import datetime
import base64
import json
import logging
import os


# Configure logging
if not os.path.exists('logs'):
    os.makedirs('logs')

log_filename = f'logs/test_run_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_filename),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class DeviceRegistrationTests(APITestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        logger.info("\n")
        logger.info("="*50)
        logger.info("Starting Device Registration Tests")
        logger.info("="*50)
    def setUp(self):
        logger.info("=== Setting up DeviceRegistrationTests ===")
        self.user = User.objects.create_user(username='testuser', password='testpass')
        logger.info(f"Created test user: {self.user.username}")
        self.client.force_authenticate(user=self.user)
        self.url = reverse('device-register')
        logger.info(f"Test URL: {self.url}")

    def test_valid_registration(self):
        logger.info("== Testing valid device registration ==")
        data = {'dev_eui': '0123456789ABCDEF'}
        logger.info(f"Request data: {data}")
        response = self.client.post(self.url, data, format='json')
        logger.info(f"Response status: {response.status_code}")
        logger.info(f"Response data: {response.data}")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('api_key', response.data)

    def test_invalid_dev_eui_format(self):
        logger.info("== Testing invalid DevEUI format ==")
        data = {'dev_eui': 'INVALIDDEVEUI'}
        logger.info(f"Request data: {data}")
        response = self.client.post(self.url, data, format='json')
        logger.info(f"Response status: {response.status_code}")
        logger.info(f"Response data: {response.data}")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_duplicate_dev_eui(self):
        logger.info("== Testing duplicate DevEUI registration ==")
        Device.objects.create(dev_eui='0123456789ABCDEF', user=self.user)
        logger.info("Created initial device with DevEUI: 0123456789ABCDEF")
        data = {'dev_eui': '0123456789ABCDEF'}
        logger.info(f"Attempting to create duplicate with data: {data}")
        response = self.client.post(self.url, data, format='json')
        logger.info(f"Response status: {response.status_code}")
        logger.info(f"Response data: {response.data}")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        
    def tearDown(self):
        logger.info("=== Cleaning up DeviceRegistrationTests ===\n\n")
        User.objects.all().delete()
        Device.objects.all().delete()

class PayloadCreateTests(APITestCase):
    def setUp(self):
        logger.info("=== Setting up PayloadCreateTests ===")
        self.user = User.objects.create_user(username='testuser', password='testpass')
        logger.info(f"Created test user: {self.user.username}")
        self.device = Device.objects.create(dev_eui='0123456789ABCDEF', user=self.user)
        logger.info(f"Created test device with DevEUI: {self.device.dev_eui}")
        self.url = reverse('create-payload')
        logger.info(f"Test URL: {self.url}")
        self.client.credentials(HTTP_X_API_KEY=self.device.api_key)
        logger.info(f"Set API key in credentials: {self.device.api_key}")

    def test_valid_payload(self):
        logger.info("== Testing valid payload submission ==")
        # Test for passing status (hex 01)
        data = {
            'devEUI': '0123456789ABCDEF',
            'fCnt': 1,
            'data': base64.b64encode(bytes.fromhex('01')).decode(),
            'rxInfo': [{
                'gatewayID': '0123456789ABCDEF',
                'name': 'test-gateway',
                'time': '2024-01-01T00:00:00Z',
                'rssi': -60,
                'loRaSNR': 7.5
            }],
            'txInfo': {
                'frequency': 868100000,
                'dr': 0
            }
        }
        logger.info(f"Request data: {json.dumps(data, indent=2)}")
        response = self.client.post(self.url, data, format='json')
        logger.info(f"Response status: {response.status_code}")
        logger.info(f"Response data: {response.data}")
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['status'], 'passing')
        
        # Test failing status (hex 00)
        data['fCnt'] = 2
        data['data'] = base64.b64encode(bytes.fromhex('00')).decode()
        response = self.client.post(self.url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['status'], 'failing')
        
        # Test failing status (hex 02)
        data['fCnt'] = 3
        data['data'] = base64.b64encode(bytes.fromhex('02')).decode()
        response = self.client.post(self.url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['status'], 'failing')

    def test_invalid_api_key(self):
        logger.info("== Testing invalid API key ==")
        self.client.credentials(HTTP_X_API_KEY='invalid-key')
        logger.info("Set invalid API key in credentials: 'invalid-key'")
        data = {
            'devEUI': '0123456789ABCDEF',
            'fCnt': 1,
            'data': base64.b64encode(b'\x01').decode(),
            'rxInfo': [{
                'gatewayID': '0123456789ABCDEF',
                'name': 'test-gateway',
                'time': '2024-01-01T00:00:00Z',
                'rssi': -60,
                'loRaSNR': 7.5
            }],
            'txInfo': {
                'frequency': 868100000,
                'dr': 0
            }
        }
        logger.info(f"Request data: {json.dumps(data, indent=2)}")
        response = self.client.post(self.url, data, format='json')
        logger.info(f"Response status: {response.status_code}")
        logger.info(f"Response data: {response.data}")
        # Print authentication and permission details
        logger.info(f"Request auth: {getattr(response.wsgi_request, 'auth', None)}")
        logger.info(f"Request user: {getattr(response.wsgi_request, 'user', None)}")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_duplicate_payload(self):
        logger.info("== Testing duplicate payload submission ==")
        data = {
            'devEUI': '0123456789ABCDEF',
            'fCnt': 1,
            'data': base64.b64encode(b'\x01').decode(),
            'rxInfo': [{
                'gatewayID': '0123456789ABCDEF',
                'name': 'test-gateway',
                'time': '2024-01-01T00:00:00Z',
                'rssi': -60,
                'loRaSNR': 7.5
            }],
            'txInfo': {
                'frequency': 868100000,
                'dr': 0
            }
        }
        logger.info("Submitting first payload")
        first_response = self.client.post(self.url, data, format='json')
        logger.info(f"First response status: {first_response.status_code}")
        logger.info(f"First response data: {first_response.data}")
        
        logger.info("Submitting duplicate payload")
        second_response = self.client.post(self.url, data, format='json')
        logger.info(f"Second response status: {second_response.status_code}")
        logger.info(f"Second response data: {second_response.data}")
        self.assertEqual(second_response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_missing_required_fields(self):
        logger.info("== Testing missing required fields ==")
        data = {
            'devEUI': '0123456789ABCDEF',
            'fCnt': 1,
            'data': base64.b64encode(b'\x01').decode(),
            'rxInfo': [{
                'gatewayID': '0123456789ABCDEF',
                # Missing 'name' field
                'time': '2024-01-01T00:00:00Z',
                'rssi': -60,
                'loRaSNR': 7.5
            }],
            'txInfo': {
                'frequency': 868100000,
                'dr': 0
            }
        }
        logger.info(f"Request data (missing 'name' field): {json.dumps(data, indent=2)}")
        response = self.client.post(self.url, data, format='json')
        logger.info(f"Response status: {response.status_code}")
        logger.info(f"Response data: {response.data}")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_invalid_base64_data(self):
        logger.info("== Testing invalid base64 data ==")
        data = {
            'devEUI': '0123456789ABCDEF',
            'fCnt': 1,
            'data': 'invalid-base64',
            'rxInfo': [{
                'gatewayID': '0123456789ABCDEF',
                'name': 'test-gateway',
                'time': '2024-01-01T00:00:00Z',
                'rssi': -60,
                'loRaSNR': 7.5
            }],
            'txInfo': {
                'frequency': 868100000,
                'dr': 0
            }
        }
        logger.info(f"Request data with invalid base64: {json.dumps(data, indent=2)}")
        response = self.client.post(self.url, data, format='json')
        logger.info(f"Response status: {response.status_code}")
        logger.info(f"Response data: {response.data}")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    
    def tearDown(self):
        logger.info("=== Cleaning up PayloadCreateTests ===\n\n")
        User.objects.all().delete()
        Device.objects.all().delete()
    
        
class TokenRenewTests(APITestCase):
    def setUp(self):
        logger.info("=== Setting up TokenRenewTests ===")
        # Create test user
        self.username = 'testuser'
        self.password = 'testpass123'
        self.user = User.objects.create_user(
            username=self.username,
            password=self.password
        )
        logger.info(f"Created test user: {self.username}")
        
        # Create initial token
        self.initial_token = Token.objects.create(user=self.user)
        logger.info(f"Created initial token: {self.initial_token.key}")
        
        self.url = reverse('token-renew')
        logger.info(f"Test URL: {self.url}")

    def test_successful_token_renewal(self):
        logger.info("== Testing successful token renewal ==")
        data = {
            'username': self.username,
            'password': self.password
        }
        logger.info(f"Request data: {data}")
        
        initial_token_key = self.initial_token.key
        logger.info(f"Initial token: {initial_token_key}")

        response = self.client.post(self.url, data, format='json')
        logger.info(f"Response status: {response.status_code}")
        logger.info(f"Response data: {response.data}")

        # Check if response is successful
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Check if token is in response
        self.assertIn('token', response.data)
        
        # Check if new token is different from old token
        new_token = response.data['token']
        self.assertNotEqual(initial_token_key, new_token)
        logger.info(f"New token generated: {new_token}")
        
        # Check if old token was deleted
        self.assertEqual(Token.objects.filter(key=initial_token_key).count(), 0)
        logger.info("Old token was successfully deleted")

    def test_missing_credentials(self):
        logger.info("== Testing missing credentials ==")
        # Test missing password
        data = {'username': self.username}
        logger.info(f"Request data (missing password): {data}")
        
        response = self.client.post(self.url, data, format='json')
        logger.info(f"Response status: {response.status_code}")
        logger.info(f"Response data: {response.data}")
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        
        # Test missing username
        data = {'password': self.password}
        logger.info(f"Request data (missing username): {data}")
        
        response = self.client.post(self.url, data, format='json')
        logger.info(f"Response status: {response.status_code}")
        logger.info(f"Response data: {response.data}")
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_invalid_credentials(self):
        logger.info("== Testing invalid credentials ==")
        data = {
            'username': self.username,
            'password': 'wrongpassword'
        }
        logger.info(f"Request data (wrong password): {data}")
        
        response = self.client.post(self.url, data, format='json')
        logger.info(f"Response status: {response.status_code}")
        logger.info(f"Response data: {response.data}")
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        
        # Test non-existent user
        data = {
            'username': 'nonexistentuser',
            'password': self.password
        }
        logger.info(f"Request data (non-existent user): {data}")
        
        response = self.client.post(self.url, data, format='json')
        logger.info(f"Response status: {response.status_code}")
        logger.info(f"Response data: {response.data}")
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        
    def tearDown(self):
        logger.info("=== Cleaning up TokenRenewTests ===\n\n")
        User.objects.all().delete()
        Token.objects.all().delete()
        
class DevicePayloadListTests(APITestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        logger.info("\n")
        logger.info("="*50)
        logger.info("Starting Device Payload List Tests")
        logger.info("="*50)

    def setUp(self):
        logger.info("=== Setting up DevicePayloadListTests ===")
        self.user = User.objects.create_user(username='testuser', password='testpass')
        self.device = Device.objects.create(dev_eui='0123456789ABCDEF', user=self.user)
        logger.info(f"Created test device with DevEUI: {self.device.dev_eui}")
        
        # Create payloads through API
        self.payload_url = reverse('create-payload')
        self.client.credentials(HTTP_X_API_KEY=self.device.api_key)
        
        # Create first payload
        data1 = {
            'devEUI': '0123456789ABCDEF',
            'fCnt': 1,
            'data': base64.b64encode(b'\x01').decode(),
            'rxInfo': [{
                'gatewayID': '0123456789ABCDEF',
                'name': 'test-gateway-1',
                'time': '2024-01-01T00:00:00Z',
                'rssi': -60,
                'loRaSNR': 7.5
            }],
            'txInfo': {
                'frequency': 868100000,
                'dr': 0
            }
        }
        self.client.post(self.payload_url, data1, format='json')
        
        # Create second payload
        data2 = {
            'devEUI': '0123456789ABCDEF',
            'fCnt': 2,
            'data': base64.b64encode(b'\x00').decode(),
            'rxInfo': [{
                'gatewayID': '0123456789ABCDEF',
                'name': 'test-gateway-2',
                'time': '2024-01-01T00:01:00Z',
                'rssi': -65,
                'loRaSNR': 6.5
            }],
            'txInfo': {
                'frequency': 868100000,
                'dr': 0
            }
        }
        self.client.post(self.payload_url, data2, format='json')
        
        self.url = reverse('device-payloads', kwargs={'dev_eui': self.device.dev_eui})
        self.client.force_authenticate(user=self.user)

    def test_valid_payload_list(self):
        logger.info("== Testing valid payload list ==")
        response = self.client.get(self.url)
        logger.info(f"Response status: {response.status_code}")
        logger.info(f"Response data: {response.data}")
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 2)

    def test_invalid_dev_eui_payload_list(self):
        logger.info("== Testing invalid DevEUI for payload list ==")
        url = reverse('device-payloads', kwargs={'dev_eui': 'INVALIDDEVEUI'})
        response = self.client.get(url)
        logger.info(f"Response status: {response.status_code}")
        logger.info("Response content: {response.content}") 
        
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_unauthorized_payload_list(self):
        logger.info("== Testing unauthorized payload list access ==")
        self.client.force_authenticate(user=None)
        
        response = self.client.get(self.url)
        logger.info(f"Response status: {response.status_code}")
        logger.info(f"Response content: {response.content}")
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def tearDown(self):
        logger.info("=== Cleaning up DevicePayloadListTests ===\n\n")
        User.objects.all().delete()
        Device.objects.all().delete()

class DeviceStatusTests(APITestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        logger.info("\n")
        logger.info("="*50)
        logger.info("Starting Device Status Tests")
        logger.info("="*50)

    def setUp(self):
        logger.info("=== Setting up DeviceStatusTests ===")
        self.user = User.objects.create_user(username='testuser', password='testpass')
        self.device = Device.objects.create(
            dev_eui='0123456789ABCDEF',
            user=self.user,
            status='passing'
        )
        logger.info(f"Created test device with DevEUI: {self.device.dev_eui}")
        
        self.client.force_authenticate(user=self.user)
        self.url = reverse('device-status', kwargs={'dev_eui': self.device.dev_eui})

    def test_valid_device_status(self):
        logger.info("== Testing valid device status retrieval ==")
        response = self.client.get(self.url)
        logger.info(f"Response status: {response.status_code}")
        logger.info(f"Response data: {response.data}")
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['dev_eui'], self.device.dev_eui)
        self.assertEqual(response.data['status'], 'passing')
        self.assertIn('last_updated', response.data)

    def test_invalid_dev_eui_status(self):
        logger.info("== Testing invalid DevEUI for status ==")
        url = reverse('device-status', kwargs={'dev_eui': 'INVALIDDEVEUI'})
        response = self.client.get(url)
        logger.info(f"Response status: {response.status_code}")
        logger.info(f"Response content: {response.content}")
        
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_unauthorized_status(self):
        logger.info("== Testing unauthorized status access ==")
        self.client.force_authenticate(user=None) 
        response = self.client.get(self.url)
        logger.info(f"Response status: {response.status_code}")
        logger.info(f"Response content: {response.content}")
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def tearDown(self):
        logger.info("=== Cleaning up DeviceStatusTests ===\n\n")
        User.objects.all().delete()
        Device.objects.all().delete()