from rest_framework import routers, serializers
from rest_framework import exceptions
from django.contrib.auth import authenticate
from .models import USER_details


class USER_Serializer(serializers.ModelSerializer):
    class Meta:
        model = USER_details
        fields = ['email','password']
 


#-------------------------------------------------------------------------


from rest_framework import serializers
from .models import USER_Entry, Driver_Entry, Hospital

class USER_EntrySerializer(serializers.ModelSerializer):
    class Meta:
        model = USER_Entry
        fields = '__all__'  # Serialize all fields

class Driver_EntrySerializer(serializers.ModelSerializer):
    class Meta:
        model = Driver_Entry
        fields = '__all__'

class HospitalSerializer(serializers.ModelSerializer):
    class Meta:
        model = Hospital
        # fields = ['license_img','landline','mobile','no_of_ambulances','established','supervisor_id_card','hospital_name','user_type','location']
        fields = '__all__'
