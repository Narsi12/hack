from django.db import models
from djongo import models
# from django.contrib.auth.models import AbstractUser




class USER_details(models.Model):
    _id=models.ObjectIdField(auto_created=True, primary_key=True, serialize=True, verbose_name='ID')
    logged_in = 'temporarily'
    logg = [( logged_in, 'temporarily'),]
    logged_in = models.CharField(max_length=20,choices=logg,default=logged_in)
    email = models.EmailField()
    password = models.CharField(max_length=138)
    user = models.CharField(max_length=200,default="user")
    date_joined = models.DateTimeField(auto_now_add=True)

    
class Post(models.Model):
    _id= models.ObjectIdField()
    user_name  = models.CharField(max_length=30)
    car_name   = models.CharField(max_length=20)
    car_number = models.CharField(max_length=10)
    service_date = models.DateTimeField(auto_now_add=True)
    phone_no   = models.CharField(max_length=10)

class Entry(models.Model):
    car = models.EmbeddedField(model_container=Post)

#----------------------------------------------------------------------------------------------------------------------------------------



class USER_Entry(models.Model):
    _id=models.ObjectIdField(auto_created=True, primary_key=True, serialize=True, verbose_name='ID')
    email = models.EmailField()
    password = models.CharField(max_length=138)
    phone_number = models.CharField(max_length=200)
    emergency_phone_number = models.CharField(max_length=200)
     



















