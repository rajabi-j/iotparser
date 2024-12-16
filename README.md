# IoT Device Management System

A robust Django REST API system for IoT device management, featuring secure device registration, payload processing, and comprehensive status monitoring.

## System Overview

### Architecture Flow
```
User Authentication → Device Registration → API Key Generation → Payload Submission → Status Updates
```

### Core Features

1. **Authentication System**
   - Token-based user authentication
   - Device-specific API key authentication
   - Secure token renewal mechanism
   - Automatic API key generation for devices

2. **Device Management**
   - Unique DevEUI registration
   - Real-time status tracking (passing/failing)
   - Device-to-user association
   - Automatic timestamp management

3. **Payload Processing**
   - Base64 data handling
   - Frame counter validation
   - Gateway information tracking
   - Signal quality monitoring
   - Automatic status updates
   - Duplicate submission prevention

## Technical Details

### Device Registration Details

**Device Model Structure:**
```python
class Device:
    user: ForeignKey to User
    dev_eui: CharField(16 chars, unique)
    status: CharField(choices=['passing', 'failing'])
    api_key: CharField(100 chars, unique)
    created_at: DateTimeField(auto)
    updated_at: DateTimeField(auto)
```

**Validation Rules:**
- DevEUI: 16-character hexadecimal string (regex: `^[0-9A-Fa-f]{16}$`)
- Unique DevEUI constraint
- Automatic API key generation using `secrets.token_urlsafe(32)`

### Payload Structure and Validation

**Payload Model:**
```python
class Payload:
    device: ForeignKey to Device
    f_cnt: IntegerField
    data: CharField(255 chars)
    decoded_data: CharField(255 chars)
    status: CharField(choices=['passing', 'failing'])
    gateway_id: CharField(16 chars)
    gateway_name: CharField(255 chars)
    gateway_time: DateTimeField
    rssi: IntegerField
    lora_snr: FloatField
    frequency: IntegerField
    dr: IntegerField
    created_at: DateTimeField(auto)
```

**Required Payload JSON Structure:**
```json
{
    "devEUI": "0123456789ABCDEF",
    "fCnt": 1,
    "data": "AQ==",
    "rxInfo": [{
        "gatewayID": "0123456789ABCDEF",
        "name": "test-gateway",
        "time": "2024-01-01T00:00:00Z",
        "rssi": -60,
        "loRaSNR": 7.5
    }],
    "txInfo": {
        "frequency": 868100000,
        "dr": 0
    }
}
```

## API Endpoints and Usage

### 1. Device Registration
- **Endpoint:** `POST /api/register/`
- **Authentication:** User Token
- **Request Body:**
  ```json
  {
      "dev_eui": "0123456789ABCDEF"
  }
  ```
- **Success Response (201):**
  ```json
  {
      "dev_eui": "0123456789ABCDEF",
      "api_key": "generated_api_key_here"
  }
  ```

### 2. Payload Submission
- **Endpoint:** `POST /api/payload/`
- **Authentication:** Device API Key (X-API-Key header)
- **Success Response (201):**
  ```json
  {
      "message": "Payload processed successfully",
      "status": "passing"
  }
  ```

### 3. Device Status
- **Endpoint:** `GET /api/device/<dev_eui>/status/`
- **Authentication:** User Token
- **Success Response (200):**
  ```json
  {
      "dev_eui": "0123456789ABCDEF",
      "status": "passing",
      "last_updated": "2024-01-01T00:01:00Z"
  }
  ```

### 4. Token Renewal
- **Endpoint:** `POST /api/token-renew/`
- **Authentication:** None
- **Request Body:**
  ```json
  {
      "username": "myuser",
      "password": "mypass"
  }
  ```
- **Success Response (200):**
  ```json
  {
      "token": "new_token_here"
  }
  ```

### 5. Device Payloads List
- **Endpoint:** `GET /api/device/<dev_eui>/payloads/`
- **Authentication:** User Token
- **Response:** List of payloads ordered by creation time

## Installation and Setup

Create and activate virtual environment:
```bash
git clone https://github.com/rajabi-j/iotparser.git
cd iotparser
```

### Local Development
1. Create and activate virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install requirements:
```bash
pip install -r requirements.txt
```

3. Run migrations:
```bash
python manage.py makemigrations
python manage.py migrate
```

4. Run development server:
```bash
python manage.py runserver
```

5. Create initial user:
```bash
python create_user.py myuser mypass
```

### Docker Setup
1. Build and run with docker-compose:
```bash
docker-compose build
docker-compose up -d
```

2. Create initial user:
```bash
docker-compose exec api python create_user.py myuser mypass
```

## Testing

### Running Tests
```bash
# Run all tests
python manage.py test

# Run specific test classes
python manage.py test devices.tests.DeviceRegistrationTests
python manage.py test devices.tests.PayloadCreateTests
python manage.py test devices.tests.TokenRenewTests
python manage.py test devices.tests.DevicePayloadListTests
python manage.py test devices.tests.DeviceStatusTests
```

### Test Logging
- Test execution logs are automatically created in the `logs` directory
- Each test run creates a new log file with timestamp: `logs/test_run_YYYYMMDD_HHMMSS.log`
- Logs include detailed information about:
  - Test setup and teardown
  - Request data and responses
  - Authentication details
  - Error messages and stack traces
  - Test execution flow

### Test Cases Overview

1. **Device Registration Tests**
   - Valid registration with proper DevEUI
   - Invalid DevEUI format handling
   - Duplicate DevEUI prevention
   - Authentication validation

2. **Payload Creation Tests**
   - Valid payload processing
   - API key validation
   - Duplicate payload prevention
   - Required field validation
   - Base64 data validation

3. **Token Management Tests**
   - Successful token renewal
   - Invalid credential handling
   - Missing credential handling

4. **Device Status Tests**
   - Status retrieval validation
   - Invalid DevEUI handling
   - Authentication requirements

5. **Payload List Tests**
   - Payload retrieval validation
   - Ordering verification
   - Authentication checks

### Test Coverage
- Authentication and authorization
- Input validation
- Error handling
- Data processing
- API response formatting
- Security measures

## Manual Testing

## Manual Testing

### 1. Initial Setup
```bash
# Create user and get token with docker
docker-compose exec api python create_user.py myuser mypass

# Create user and get token without docker
python create_user.py myuser mypass

# Save token
token="uesr_token_here"
```

### 2. Device Registration
```bash
curl -X POST http://localhost:8000/api/register/ \
  -H "Authorization: Token ${token}" \
  -H "Content-Type: application/json" \
  -d '{"dev_eui": "0123456789ABCDEF"}'

# Save API key
api_key="returned_api_key"
```

### 3. Create Payload
```bash
# Passing Status
curl -X POST http://localhost:8000/api/payload/ \
  -H "X-API-Key: ${api_key}" \
  -H "Content-Type: application/json" \
  -d '{
    "devEUI": "0123456789ABCDEF",
    "fCnt": 1,
    "data": "AQ==",
    "rxInfo": [{
      "gatewayID": "0123456789ABCDEF",
      "name": "test-gateway",
      "time": "2024-01-01T00:00:00Z",
      "rssi": -60,
      "loRaSNR": 7.5
    }],
    "txInfo": {
      "frequency": 868100000,
      "dr": 0
    }
  }'
```

```bash
# Failing Status
curl -X POST http://localhost:8000/api/payload/ \
  -H "X-API-Key: ${api_key}" \
  -H "Content-Type: application/json" \
  -d '{
    "devEUI": "0123456789ABCDEF",
    "fCnt": 2,
    "data": "AA==",
    "rxInfo": [{
      "gatewayID": "0123456789ABCDEF",
      "name": "test-gateway",
      "time": "2024-01-01T00:00:00Z",
      "rssi": -60,
      "loRaSNR": 7.5
    }],
    "txInfo": {
      "frequency": 868100000,
      "dr": 0
    }
  }'
```

### 4. Token Renewal
```bash
curl -X POST http://localhost:8000/api/token-renew/ \
  -H "Content-Type: application/json" \
  -d '{
    "username": "myuser",
    "password": "mypass"
  }'
```


### 5. List Device Payloads
```bash
# List payloads for a device
curl -X GET http://localhost:8000/api/device/0123456789ABCDEF/payloads/ \
  -H "Authorization: Token ${token}"
```

### 6. Get Device Status
```bash
# Get device status
curl -X GET http://localhost:8000/api/device/0123456789ABCDEF/status/ \
  -H "Authorization: Token ${token}"
```

## Error Handling

| Status Code | Description | Common Causes |
|-------------|-------------|---------------|
| 400 | Bad Request | Invalid DevEUI format, missing required fields |
| 401 | Unauthorized | Invalid/missing token or API key |
| 404 | Not Found | Device not found, invalid endpoint |
| 409 | Conflict | Duplicate DevEUI or payload |
| 500 | Server Error | Internal processing error |

## Security Considerations

1. **Authentication**
   - Token-based user authentication
   - API key validation for devices
   - Automatic token renewal system

2. **Data Validation**
   - Strict input format validation
   - Duplicate submission prevention
   - Required field verification

3. **Access Control**
   - User-device association
   - Endpoint-specific authentication
   - Permission-based access

## Performance Considerations

1. **Database**
   - Unique indexes on DevEUI and API keys
   - Timestamp tracking for all records

2. **API Design**
   - Efficient error handling
   - Clear response formatting

3. **Scalability**
   - Independent device processing
   - Docker containerization support