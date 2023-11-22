from contextvars import Token
import json
import jwt
import logging
from django.contrib.auth.models import User, Group
from django.forms import EmailField
# from app.encrypt_decrypt import decrypt, encrypt
from app.serializers import *
from app.serializers import USER_Serializer
from django.views import View
from django.http import JsonResponse
from rest_framework import status
from myproject import settings
from django.shortcuts import get_object_or_404, get_list_or_404, render
from rest_framework.views import APIView
from rest_framework.generics import CreateAPIView,ListCreateAPIView
from rest_framework.response import Response
from .models import *
from .models import USER_details
from django.contrib.auth import authenticate
from django.db.models import Q
from django.http import HttpResponse
import pymongo
import datetime
import secrets
from .backends import EmailBackend
from datetime import datetime, timedelta
from rest_framework.exceptions import AuthenticationFailed
from bson import ObjectId
from .permissions import CustomIsauthenticated
from django.contrib.auth.hashers import make_password, check_password
from django.utils.decorators import method_decorator
from rest_framework.exceptions import APIException
from .utils import token_required
from django.conf import settings
from django.core.mail import send_mail
from django.core.mail import EmailMessage
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
JWT_SECRET_KEY = 'django-insecure-6i9o@jxm94t!sao=x%*6yhx9fyht^62ir(wzw5sre^*a%lk02'
JWT_ACCESS_TOKEN_EXPIRATION = 60
JWT_REFRESH_TOKEN_EXPIRATION = 1440
JWT_ALGORITHM = 'HS256'

myclient = pymongo.MongoClient("mongodb://localhost:27017/")
mydb = myclient["kalyani"]
mycol1 = mydb['app_driver_entry']
mycol2 = mydb['app_hospital']
mycol3 = mydb['app_user_entry']
tokens = mydb['tokens']

logger = logging.getLogger("django")    
class ChangePassword(CreateAPIView):
    permission_classes = [CustomIsauthenticated]
    @method_decorator(token_required)
    def post(self,request):
        user_id= ObjectId(request.user._id)
        user = mycol1.find_one({"_id":user_id}) 
        data = request.data
        email = user['email']
        oldpassword = data['password']
        newpassword = data['newpassword']
        try:
            user_obj = USER_details.objects.get(email=email)
        except USER_details.DoesNotExist:
            logger.warning("User not found")
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        if not check_password(oldpassword, user_obj.password):
            logger.warning("Invalid old password")
            return Response({'error': 'Invalid old password'}, status=status.HTTP_400_BAD_REQUEST)
            
        user_obj.password=make_password(newpassword)
        user_obj.save()

        logger.info("Password changed successfully")
        return Response({'success': 'Password changed successfully'}, status=status.HTTP_200_OK)


class NewPassordGenerate(CreateAPIView):
    def post(self,request):
        data = request.data
        email = data['email']
        oldpassword = data['password']
        newpassword = data['newpassword']
        try:
            user_obj = USER_details.objects.get(email=email)
        except USER_details.DoesNotExist:
            logger.warning("User not found")
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        if not check_password(oldpassword, user_obj.password):
            logger.warning("Invalid old password")
            return Response({'error': 'Invalid old password'}, status=status.HTTP_400_BAD_REQUEST)
            
        user_obj.password=make_password(newpassword)
        user_obj.save()

        logger.info("Password changed successfully")
        return Response({'success': 'Password changed successfully'}, status=status.HTTP_200_OK)
    

class LogoutView(APIView):
    permission_classes = [CustomIsauthenticated]

    def post(self, request):
        try:
            user_id = request.user._id
            auth_header = request.headers.get('Authorization')
            
            if auth_header is None:
                logger.info(f"Authorization header is missing")

                raise APIException("Authorization header is missing")

            a_token = auth_header.split()[1]
            user_data = tokens.find({})  # here we are getting all token collection information
            information = []
            
            for info in user_data:
                if (datetime.utcnow() - info['created_date']).days >= 1:
                    # if token created date is greater than or equal to 1 day, remove the token from collection
                    information.append(info['_id'])

            tokens.remove({"_id": {"$in": information}})
            
            tokens.update(
                {"user_id": str(user_id), "access_token": a_token},
                {"$set": {"active": False}}
            )
            logger.info("logout successfully")
            return Response('Logout successfully')
        
        except KeyError as e:
            logger.error(f"KeyError: {str(e)}")
            raise APIException(f"KeyError: {str(e)}")
        
        except IndexError as e:
            logger.error(f"IndexError: {str(e)}")
            raise APIException(f"IndexError: {str(e)}")
        
        except Exception as e:
            logger.error(str(e))
            raise APIException(str(e))



def generate_otp(length=6):
        """Generates a random OTP of the specified length."""
        return secrets.token_hex(length // 2 + 1)[:length]


class ForgotPassword(APIView):
    def post(self,request):
        data= request.data
        email=data["email"]
        try:
            user_obj = USER_details.objects.get(email=email)
        except USER_details.DoesNotExist:
            logger.info({'error': 'Email doesn\'t exist'})
            return Response({'error': 'Email doesn\'t exist'}, status=status.HTTP_404_NOT_FOUND)
        if user_obj is not None:
            otp = generate_otp()
            hased_password = make_password(otp)
            mycol3.update(
                    {"email": email},
                    {
                        "$set": {"password":hased_password}
                    }
                )
            email_msg = EmailMessage(
            'Email Details',
            f"RESET PASSWORD \n Hey there!\n It looks like you are trying to reset password.\n\nYOUR NEW LOGIN DETAILS:\n password: {otp}\n Email: {email}",
            settings.EMAIL_HOST_USER,
            [email],
            )
            email_msg.send(fail_silently=True)
            logger.info({"New password generated successfully"})
            return Response({"message":"New password generated successfully and send to your respective mail id"})
        else:
            logger.info({"invalid data"})
            return JsonResponse({"message":"invalid data"})
        
    
#----------------------------------------------------------------------------------------------------------------------------------

from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from .models import USER_Entry, Driver_Entry, Hospital, long_lat_email
from .serializers import USER_EntrySerializer, Driver_EntrySerializer, HospitalSerializer, LongLatEmailSerializer, AmbulanceRequiestCallSerializer
from mail_notification.connection import MailConfig
from django.core.mail import send_mail
from googlemaps import Client as GoogleMaps
import requests
from .decorator import calculate_distance


myclient = pymongo.MongoClient("mongodb://localhost:27017/")
mydb = myclient["ambulance_tracker"]
mycol1 = mydb['app_driver_entry']
mycol2 = mydb['app_hospital']
mycol3 = mydb['app_user_entry']
tokens = mydb['tokens']
user_requests = mydb["user_raise_request"]



#registration api
class RegistrationAPIView(APIView):
    def post(self, request):
        # import pdb;pdb.set_trace()
        user_type = request.data.get('user_type')
        password = request.data.get('password')
        email = request.data.get('email')

       
        if not email:
            return Response({"error": "Email is required"}, status=status.HTTP_400_BAD_REQUEST)
        
         # Hash the password
        hashed_password = make_password(password) 
        request.data['password'] = hashed_password
        # mutable_data = request.data.copy()
        # mutable_data['password'] = hashed_password

        
        existing_user = USER_Entry.objects.filter(email=email).first() or Driver_Entry.objects.filter(email=email).first() or Hospital.objects.filter(email=email).first()
        if existing_user is not None:
            return JsonResponse({'Message': 'Email already exists'}, status=status.HTTP_400_BAD_REQUEST)

        if user_type == 'user':
            serializer = USER_EntrySerializer(data=request.data)


        elif user_type == 'driver':
            serializer = Driver_EntrySerializer(data=request.data)
            demo=MailConfig(mail_user="harikishansuri1998@gmail.com",password="mita ypfc xjel khyy")
            demo.send_mail(to_mail=email,subject="text",body=f"Dear user, your account details are being processed.\n Email: {email}")
            demo.close_conn()
            
        elif user_type == 'hospital':
            location_data_str = request.data.get('location')
            location_data = json.loads(location_data_str)
            request.data['location'] = location_data
            serializer = HospitalSerializer(data=request.data)
            demo=MailConfig(mail_user="harikishansuri1998@gmail.com",password="mita ypfc xjel khyy")
            demo.send_mail(to_mail=email,subject="text",body=f"Dear user, your account details are being processed.\n Email: {email}")
            demo.close_conn()
        else:
            return Response({"error": "Invalid user_type"}, status=status.HTTP_400_BAD_REQUEST)

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class Login_View(APIView):
    def post(self,request):
        data = request.data
        email = data.get('email',None)
        password = data.get('password',None)

        user=EmailBackend.authenticate(self, request, username=email, password=password)
        if user is not None:
            token_payload = {
                'user_id': str(user._id),
                'exp': datetime.utcnow() + timedelta(minutes=settings.JWT_SETTINGS['JWT_ACCESS_TOKEN_EXPIRATION']),
                'iat': datetime.utcnow()
                }
            access_token = jwt.encode(token_payload, settings.JWT_SETTINGS["JWT_SECRET_KEY"], settings.JWT_SETTINGS["JWT_ALGORITHM"])

            refresh_token_payload = {
                'user_id': str(user._id),
                'exp': datetime.utcnow() + timedelta(days=settings.JWT_SETTINGS['JWT_REFRESH_TOKEN_EXPIRATION']),
                'iat': datetime.utcnow()
                }
            refresh_token = jwt.encode(refresh_token_payload, settings.JWT_SETTINGS["JWT_REFRESH_SECRET_KEY"], settings.JWT_SETTINGS["JWT_ALGORITHM"])

            tokens.insert_one({
                "user_id":str(user._id),
                "access_token":access_token,
                "refresh_token":refresh_token,
                "active":True,
                "created_date":datetime.utcnow()
            })

            collections = [mycol1, mycol2, mycol3]
            for collection in collections:
                details = collection.find_one({"email": email})
                if details:
                    usertype = details.get('user_type')

            return JsonResponse({
                    "status": "success",
                    "msg": "user successfully authenticated",
                    "token": access_token,
                    "refresh_token": refresh_token,
                    "email":email,
                    "usertype":usertype
                })
        else:
            return JsonResponse({"message":"invalid data"})



class NearHospitalsList(APIView):
    def get(self, request):
        latitude = request.GET.get("latitude")
        longitude = request.GET.get("longitude")
        api_key = 'AIzaSyBO0HZnIuHmIB7qalDQ-jTsT4bXbkcFLZM'
        gmaps = GoogleMaps(api_key)
        radius = 5000
        location = (latitude, longitude)
 
        url = f"https://maps.googleapis.com/maps/api/place/nearbysearch/json?location={latitude},{longitude}&radius={radius}&type=hospital&key={api_key}"
 
        response = requests.get(url)
 
        if response.status_code == 200:
            hospitals_data = response.json()
       
            if 'results' in hospitals_data:
                nearby_hospitals = hospitals_data['results']
                print("\nNearby Hospitals:")
                hospitals_json = []
                for hospital in nearby_hospitals:
                    hospital_name = hospital['name']
                    hospital_opening_hours = hospital.get('opening_hours', {}).get('open_now', None)
                    hospital_location = hospital['geometry']['location']
                    hospital_lat = hospital_location['lat']
                    hospital_lng = hospital_location['lng']
 
                    ambulance_avb = mycol2.find_one({"hospital_name":hospital_name})
                    if ambulance_avb is not None:
                        ambulance = "False" if ambulance_avb['no_of_ambulances'] =="0" else "True"
                    else:
                        ambulance = "hospital not rejected"
 
                    hospital_info = {
                        "name": hospital_name,
                        "latitude": hospital_lat,
                        "longitude": hospital_lng,
                        "open_now": str(hospital_opening_hours) if hospital_opening_hours else 'Not available',
                        "ambulance_available": ambulance
                    }
                    hospitals_json.append(hospital_info)
 
                return Response(hospitals_json, status=status.HTTP_200_OK)
            else:
                return Response({"message": "No hospital data found in the specified radius."}, status=status.HTTP_404_NOT_FOUND)
        else:
            return Response({"message": "Failed to fetch data from Google Places API."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        

from .decorator import address_decorator

class get_address_from_long_lat(APIView):
    @address_decorator
    def get(self, request, latitude, longitude, result):
        return JsonResponse({"latitude": latitude, "longitude": longitude, "address": result})


class get_hospital_details(APIView):
    def post(self,request,hospital_name=None):
        lat1 = request.GET.get('latitude', None)
        lon1 = request.GET.get('longitude', None)
        print(hospital_name)
        data =mycol2.find_one({"hospital_name":hospital_name})
        print(data)
        try:
            if lat1 is None or lon1 is None:
                return Response({"message": "Latitude or longitude values are missing."}, status=400)

            # if distance is not None:
            if hospital_name is not None:
                data =mycol2.find_one({"hospital_name":hospital_name})
                print(data)
                location_dict = data.get('location', {})
                lat2 = location_dict.get('latitude', None)
                lon2 = location_dict.get('longitude', None)
                distance,maps_link = calculate_distance(lat1, lon1, lat2, lon2)
                
                if distance is not None:
                    response ={
                        "hospital_name":hospital_name,
                        "address": data['location'],
                        "mobile":data["mobile"],
                        "landline":data["landline"],
                        "no_of_ambulances":data["no_of_ambulances"],
                        "distance": distance,
                        "maps_link":maps_link
                    }
                    return Response(response, status=status.HTTP_200_OK)
                else:
                    return Response({"message": "Failed to calculate distance."}, status=500)
            else:
                return Response({"message": "No hospital data found in the specified data."}, status=status.HTTP_404_NOT_FOUND)
       
            
        except Exception as e:
            raise APIException(str(e))

from .permissions import CustomIsauthenticated, DriverCustomIsauthenticated, HospitalCustomIsauthenticated
# views.py
class Userprofileview(APIView):
    def get(self, request, user_type=None):
        try:
            user_id = ObjectId(request.user._id)

            if user_type is not None:
                if user_type == 'user':
                    self.permission_classes = [CustomIsauthenticated]
                    user = mycol3.find_one({"_id": user_id})
                    
                elif user_type == 'driver':
                    self.permission_classes = [DriverCustomIsauthenticated]
                    user = mycol1.find_one({"_id": user_id})
                elif user_type == 'hospital':
                    self.permission_classes = [HospitalCustomIsauthenticated]
                    user = mycol2.find_one({"_id": user_id})
                else:
                    return Response({"error": "Invalid user_type"}, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({"message": "user_type values are missing."}, status=400)

            if user is not None:
                user['_id'] = str(user['_id'])
                logger.info({"request satisfyed"})
                return Response({"Data": user}, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error({str(e)})
            return Response({"error": str(e)}, status=500)

from django.core.exceptions import MultipleObjectsReturned


class PostCallLongLatEmail(APIView):
    def post(self, request, *args, **kwargs):
        data = request.data
        email =data['email']
        serializer = LongLatEmailSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
    def get(self, request):
        email = request.GET.get('email', None)
        existing_user = long_lat_email.objects.filter(email=email).first()
        if existing_user is not None:
            return JsonResponse({'Message': 'Email already exists'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            data = long_lat_email.objects.get(email=email)
            serializer = LongLatEmailSerializer(data)
            return Response(serializer.data)
        except long_lat_email.DoesNotExist:
            return Response({"message": "email not found"}, status=status.HTTP_404_NOT_FOUND)
        except MultipleObjectsReturned:
            return Response({"message": "Multiple objects found for the given email"}, status=status.HTTP_400_BAD_REQUEST)


class AmbulanceRequiestCall(APIView):
    def post(self, request, *args, **kwargs):
        data = request.data
        serializer = AmbulanceRequiestCallSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class Userprofileview_update(APIView):
    def put(self, request, user_type=None):
        try:
            user_id = ObjectId(request.user._id)
            print(user_id)
             
            if user_type is not None:
                if user_type == 'user':
                    self.permission_classes = [CustomIsauthenticated]
                    info = mycol3.find_one({"_id":user_id})
                    email = info['email']
                     
                    user_data = request.data
                    user = mycol3.find_one_and_update({"_id": user_id,"email":email},
                                         {
                                             "$set":{
                                                 "name":user_data['name'],"phone_number":user_data["phone_number"],"emergency_phone_number":user_data['emergency_phone_number'],
                                                 "location":user_data['location']
                                             }
                                         })
                elif user_type == 'driver':
                    self.permission_classes = [DriverCustomIsauthenticated]
                    driver_data = request.data
                    # id_card_file = request.FILES.get('id_card')
                    # hospital_license_file = request.FILES.get('hospital_license')
                    info1 = mycol1.find_one({"_id": user_id})
                    email = info1['email']
                    user = mycol1.find_one_and_update({"_id": user_id,"email":email},
                                         {
                                             "$set":{
                                                 "name":driver_data['name'],"hospital_name":driver_data["hospital_name"],
                                                 "phone_num":driver_data['phone_num'],"vehicle_num":driver_data['vehicle_num']
                                             }
                                         })
                     
 
                elif user_type == 'hospital':
                    self.permission_classes = [HospitalCustomIsauthenticated]
                    hospital_data = request.data
                    info2 = mycol2.find_one({"_id": user_id})
                    email = info2['email']
                    user = mycol2.find_one_and_update({"_id": user_id,"email":email},
                                         {
                                             "$set":{
                                                 "mobile":hospital_data['mobile'],"no_of_ambulances":hospital_data["no_of_ambulances"]
                                             }
                                         })
                     
                else:
                    return Response({"error": "Invalid user_type"}, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({"message": "user_type values are missing."}, status=400)
 
            if user is not None:
                user['_id'] = str(user['_id'])
                return Response({"Data": user}, status=status.HTTP_200_OK)
 
        except Exception as e:
            return Response({"error": str(e)}, status=500)
        
class RaiseRequest(APIView):
    permission_classes = [CustomIsauthenticated]

    @address_decorator
    def post(self, request, latitude=None, longitude=None, result=None):
        user_id = request.user._id
        user = mycol3.find_one({"_id": user_id})
        registered_location = user.get("location", None)
        latitude = request.data.get("latitude")
        longitude = request.data.get("longitude")
        hospital = request.data.get("hospital",None)

        if hospital is not None:
                print(hospital)
                data =mycol2.find_one({"hospital_name":hospital})
                location_dict = data.get('location', {})
                lat2 = location_dict.get('latitude', None)
                lon2 = location_dict.get('longitude', None)
                distance,maps_link = calculate_distance(latitude, longitude, lat2, lon2)

        
        data = {
            "name": user["name"],
            "phone_number": user["phone_number"],
            "registered_location": registered_location,
            "route_map": {
                "maps_link":maps_link
            },
            "distance": distance,
        }
        existing_user = user_requests.find_one({"user_id": user_id})

        if existing_user:
            return Response({"error": "User request already exists."}, status=status.HTTP_400_BAD_REQUEST)
        else:
            user_requests.insert_one({
                "user_id": user_id,
                "name": user["name"],
                "phone_number": user["phone_number"],
                "registered_location": registered_location,
                "route_map": {
                    "maps_link": maps_link
                },
                "distance": distance,
            })

            return Response(data)
        


class hospital_Dash_bord(APIView):
    def get(self, request):
        user = user_requests.find({})
        complete_info = []
        
        for patient in user:
            patient_info = {
                'user_id': str(patient['user_id']),
                'name': patient['name'],
                'phone_number': patient['phone_number'],
                'registered_location': {
                    'latitude': patient['registered_location']['latitude'],
                    'longitude': patient['registered_location']['longitude']
                },
                'route_map': {
                    'maps_link': patient['route_map']['maps_link']
                },
                'distance': patient['distance'],
            }
            complete_info.append(patient_info)
        
        return Response(complete_info)


class hospital_request_Accept(APIView):
    permission_classes = [HospitalCustomIsauthenticated]

    def post(self, request):
        hospital_user_id = request.user._id
        request_status = "accepted"
        patient_user_id = request.data.get("patient_user_id", None)
        patient_id = ObjectId(patient_user_id)
        if not patient_user_id:
            return Response({'error': 'Patient user ID is missing in the request'}, status=status.HTTP_400_BAD_REQUEST)
        user_request = user_requests.find_one_and_update(
            {"user_id": patient_id},
            {
                "$set": {
                    "status": request_status,
                    "hospital_id": hospital_user_id
                }
            }
        )
        if user_request:
            return Response({'msg': 'User request is accepted'})
        else:
            return Response({'error': 'User request not found'}, status=status.HTTP_404_NOT_FOUND)


