from django.urls import include, path
from rest_framework import routers
from .views import  ChangePassword,Register,LoginView,LogoutView,ForgotPassword,NewPassordGenerate ,RegistrationAPIView,NearHospitalsList,LoginViewAPIView
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
   
   path(r'register/', Register.as_view(), name='Register'),
   path(r'register_user/', RegistrationAPIView.as_view(), name='Register'),#new added
   path(r'near_hospitals_list/', NearHospitalsList.as_view(), name='Register'), #new added
   path(r'login/', LoginView.as_view(), name='LoginView'),
   path(r'login_view/', LoginViewAPIView.as_view(), name='LoginView'), #new added
   path(r'logout/', LogoutView.as_view(),name='Logout'),
   path(r'changepassword/', ChangePassword.as_view()),
   path(r'forgotPassword/', ForgotPassword.as_view(), name='ForgotPassword'),
   path(r'NewPassordGenerate/',NewPassordGenerate.as_view()),
   path(r'swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
   path(r'redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
   path('api-auth/', include('rest_framework.urls', namespace='rest_framework')),
  

]




from django.conf import settings

from django.conf.urls.static import static

# if settings.DEBUG:

urlpatterns += static(settings.MEDIA_URL,
document_root=settings.MEDIA_ROOT)