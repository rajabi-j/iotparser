import os
import django
from django.contrib.auth.models import User

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'iot_parser.settings')
django.setup()

def create_user(username, password):
    try:
        user = User.objects.create_user(username=username, password=password)
        print(f"User '{username}' created successfully")
        
        # Create auth token
        from rest_framework.authtoken.models import Token
        token = Token.objects.create(user=user)
        print(f"Auth Token: {token.key}")
        
    except Exception as e:
        print(f"Error creating user: {e}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Usage: python create_user.py username password")
    else:
        create_user(sys.argv[1], sys.argv[2])