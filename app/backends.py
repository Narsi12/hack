# from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model
from .models import USER_details,USER_Entry,Driver_Entry,Hospital
from rest_framework.exceptions import AuthenticationFailed,PermissionDenied
from django.contrib.auth.hashers import check_password
from django.core.exceptions import ObjectDoesNotExist


class EmailBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):

        try:
            # Try to get a user from each model
           
            user = USER_Entry.objects.filter(email=username).first() or Driver_Entry.objects.filter(email=username).first() or Hospital.objects.filter(email=username).first()

            # If no user is found, raise AuthenticationFailed
            if user is None:
                raise AuthenticationFailed("Email is not valid")

            # Check the password
            if not check_password(password, user.password):
                raise PermissionDenied("Password is not valid")

            return user

        except ObjectDoesNotExist:
            # Handle the case when the email doesn't exist in any model
            raise AuthenticationFailed("Email doesn't exist")
