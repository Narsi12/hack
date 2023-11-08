from rest_framework import routers, serializers
from rest_framework import exceptions
from django.contrib.auth import authenticate
from .models import USER_details


class USER_Serializer(serializers.ModelSerializer):
    class Meta:
        model = USER_details
        fields = ['email','password']





class Services_ownerseri(serializers.ModelSerializer):
    class Meta:
        model=USER_details
        fields=['email','password','date_joined']

