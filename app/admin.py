from django.contrib import admin
from .models import USER_details,USER_Entry,Driver_Entry,Hospital


class DriverEntryAdmin(admin.ModelAdmin):
    list_display = ['name', 'hospital_name', 'vehicle_num', 'phone_num', 'license']

admin.site.register(Driver_Entry, DriverEntryAdmin)

admin.site.register(USER_details)
admin.site.register(USER_Entry)
# admin.site.register(Driver_Entry)
admin.site.register(Hospital)
