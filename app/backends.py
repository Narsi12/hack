# from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model
from .models import USER_details
from rest_framework.exceptions import AuthenticationFailed,PermissionDenied
from django.contrib.auth.hashers import check_password

class EmailBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        # UserModel = User()
        pass
         