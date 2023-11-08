# Generated by Django 4.1.13 on 2023-11-08 07:22

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0003_alter_userdetail_hospital_license_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='User11',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('user_type', models.CharField(max_length=20)),
                ('email', models.EmailField(max_length=254)),
                ('password', models.CharField(max_length=128)),
                ('phone_number', models.CharField(blank=True, max_length=15, null=True)),
                ('emergency_phone_number', models.CharField(blank=True, max_length=15, null=True)),
                ('driver_name', models.CharField(blank=True, max_length=100, null=True)),
                ('hospital_name', models.CharField(blank=True, max_length=100, null=True)),
                ('license_image', models.ImageField(blank=True, null=True, upload_to='users/driving')),
                ('vehicle_number', models.CharField(blank=True, max_length=20, null=True)),
                ('location_access', models.BooleanField(default=False)),
                ('hospital_license', models.ImageField(blank=True, null=True, upload_to='users/hospital')),
            ],
        ),
        migrations.RemoveField(
            model_name='userdetail',
            name='user_profile',
        ),
        migrations.RemoveField(
            model_name='userprofile',
            name='user',
        ),
        migrations.DeleteModel(
            name='CustomUser',
        ),
        migrations.DeleteModel(
            name='UserDetail',
        ),
        migrations.DeleteModel(
            name='UserProfile',
        ),
    ]