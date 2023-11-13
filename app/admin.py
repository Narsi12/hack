from django.contrib import admin
from .models import USER_details,USER_Entry,Driver_Entry,Hospital


class DriverEntryAdmin(admin.ModelAdmin):
    list_display = ['name', 'hospital_name', 'vehicle_num', 'phone_num', 'location','email'
    ]

admin.site.register(Driver_Entry, DriverEntryAdmin)

class HospitalEntryAdmin(admin.ModelAdmin):
    list_display = ['hospital_name','mobile', 'email', 'location'
    ]

class UserEntryAdmin(admin.ModelAdmin):
    list_display = ['name','email','phone_number'
    ]

admin.site.register(USER_details)
admin.site.register(USER_Entry,UserEntryAdmin)
# admin.site.register(Driver_Entry)
admin.site.register(Hospital,HospitalEntryAdmin)


# class AgentAdmin(admin.ModelAdmin):
#     list_display = ('hospital_name', 'status')
#     list_filter = ('status',)  # Add this line
#     actions = ['approve_agents']

#     def approve_agents(self, request, queryset):
#         for agent in queryset:
#             agent.status = 'approved'
#             agent.save()
#         self.message_user(request, 'Selected agents have been approved.')

#     approve_agents.short_description = 'Approve selected agents'

# admin.site.register(Hospital, AgentAdmin)
