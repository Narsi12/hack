from django.urls import include, path
from rest_framework import routers
from .views import  ChangePassword,LogoutView,ForgotPassword,NewPassordGenerate ,RegistrationAPIView,NearHospitalsList,Login_View,get_address_from_long_lat, get_hospital_details,Userprofileview ,PostCallLongLatEmail, Userprofileview_update, RaiseRequest, hospital_request_Accept, hospital_Dash_bord
# from .views import get_hospital_details,Userprofileview ,PostCallLongLatEmail, Userprofileview_update
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from rest_framework import permissions
from . import views



schema_view = get_schema_view(
   openapi.Info(
      title="User API",
      default_version='v1',
      description="User related all API's",
      terms_of_service="https://www.google.com/policies/terms/",
      contact=openapi.Contact(email="contact@snippets.local"),
      license=openapi.License(name="BSD License"),
   ),
   public=True,
   permission_classes=(permissions.AllowAny,),
)



urlpatterns = [
   path(r'register_user/', RegistrationAPIView.as_view(), name='Register'),#new added
   path(r'near_hospitals_list/', NearHospitalsList.as_view(), name='Register'), #new added
   path(r'login_view/', Login_View.as_view(), name='LoginView'), #new added
   path(r'get_address_from_long_lat/',get_address_from_long_lat.as_view(),name='get_address_from_long_lat'),#new added
   path(r'get_hospital_details/<str:hospital_name>',get_hospital_details.as_view(),name='GetHospitalsDetails'),#new added
   path(r'logout/', LogoutView.as_view(),name='Logout'),
   path(r'Userprofileview/<str:user_type>',Userprofileview.as_view(),name='Userprofileview'),#new added
   path(r'changepassword/', ChangePassword.as_view()),
   path(r'forgotPassword/', ForgotPassword.as_view(), name='ForgotPassword'),
   path(r'NewPassordGenerate/',NewPassordGenerate.as_view()),
   path(r'swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
   path(r'redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
   path('api-auth/', include('rest_framework.urls', namespace='rest_framework')),

   path(r'PostCallLongLatEmail/',PostCallLongLatEmail.as_view(),name='PostCallLongLatEmail'),
   path(r'Userprofileview_update/<str:user_type>',Userprofileview_update.as_view(),name='Userprofileview_update'),
   path(r'user_request/', RaiseRequest.as_view(), name='Register'),
   path(r'accepted_user_request/', hospital_request_Accept.as_view(), name='Register'),
   path(r'get_all_user_requests/', hospital_Dash_bord.as_view(), name='Register'),
]




from django.conf import settings

from django.conf.urls.static import static

# if settings.DEBUG:

urlpatterns += static(settings.MEDIA_URL,
document_root=settings.MEDIA_ROOT)