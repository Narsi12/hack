# Generated by Django 4.1.13 on 2023-11-08 07:46

from django.db import migrations, models
import djongo.models.fields


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0005_delete_user11'),
    ]

    operations = [
        migrations.CreateModel(
            name='Driver_Entry',
            fields=[
                ('_id', djongo.models.fields.ObjectIdField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('email', models.EmailField(max_length=254)),
                ('password', models.CharField(max_length=138)),
                ('name', models.CharField(max_length=200)),
                ('hospital_name', models.CharField(max_length=200)),
                ('license', models.ImageField(blank=True, null=True, upload_to='licenses/')),
                ('vehicle_num', models.CharField(max_length=255)),
                ('phone_num', models.CharField(max_length=255)),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='Hospital',
            fields=[
                ('_id', djongo.models.fields.ObjectIdField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('email', models.EmailField(max_length=254)),
                ('password', models.CharField(max_length=138)),
                ('location', models.CharField(max_length=255)),
                ('license_img', models.ImageField(blank=True, null=True, upload_to='hospital/')),
                ('phone', models.CharField(max_length=255)),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='USER_Entry',
            fields=[
                ('_id', djongo.models.fields.ObjectIdField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('email', models.EmailField(max_length=254)),
                ('password', models.CharField(max_length=138)),
                ('phone_number', models.CharField(max_length=200)),
                ('emergency_phone_number', models.CharField(max_length=200)),
            ],
            options={
                'abstract': False,
            },
        ),
    ]
