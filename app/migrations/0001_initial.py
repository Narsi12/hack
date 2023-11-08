# Generated by Django 4.1.13 on 2023-11-08 04:41

import app.models
from django.db import migrations, models
import djongo.models.fields


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Entry',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('car', djongo.models.fields.EmbeddedField(model_container=app.models.Post)),
            ],
        ),
        migrations.CreateModel(
            name='Post',
            fields=[
                ('_id', djongo.models.fields.ObjectIdField(auto_created=True, primary_key=True, serialize=False)),
                ('user_name', models.CharField(max_length=30)),
                ('car_name', models.CharField(max_length=20)),
                ('car_number', models.CharField(max_length=10)),
                ('service_date', models.DateTimeField(auto_now_add=True)),
                ('phone_no', models.CharField(max_length=10)),
            ],
        ),
        migrations.CreateModel(
            name='USER_details',
            fields=[
                ('_id', djongo.models.fields.ObjectIdField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('logged_in', models.CharField(choices=[('temporarily', 'temporarily')], default='temporarily', max_length=20)),
                ('email', models.EmailField(max_length=254)),
                ('password', models.CharField(max_length=138)),
                ('user', models.CharField(default='user', max_length=200)),
                ('date_joined', models.DateTimeField(auto_now_add=True)),
            ],
        ),
    ]