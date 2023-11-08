import jwt
from .models import USER_details
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from bson import ObjectId
JWT_SECRET_KEY = 'vqua1i2qh8&i!w&mfkeo^uex0v*(u)08x-x!q)ggv!+k94rxxy'
JWT_ACCESS_TOKEN_EXPIRATION = 60
JWT_REFRESH_TOKEN_EXPIRATION = 1440
JWT_ALGORITHM = 'HS256'
        
class JWTAuthentication(BaseAuthentication):
    """
    Allows access only to authenticated users with valid JWT tokens.
    """

    def authenticate(self, request):
        auth_header = request.headers.get('Authorization')
        if auth_header is None:
            return None
        try:
            _, token = auth_header.split()
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        except (ValueError, jwt.exceptions.DecodeError, jwt.exceptions.ExpiredSignatureError):
            raise AuthenticationFailed('Invalid token.')
        try:
            user = USER_details.objects.get(_id=ObjectId(payload['user_id']))
        except USER_details.DoesNotExist:
            raise AuthenticationFailed('User not found.')
        return (user, None)
    