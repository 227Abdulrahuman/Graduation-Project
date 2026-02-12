from django.contrib import admin
from . import models

admin.site.register(models.Domain)
admin.site.register(models.Target)

@admin.register(models.Subdomain)
class SubdomainAdmin(admin.ModelAdmin):
    list_display = ("hostname", "ip", "cname", "is_alive")
    list_filter = ("domain",)

@admin.register(models.WebApplication)
class WebAppAdmin(admin.ModelAdmin):
    list_display = ("url", "status_code", "title", "content_length", "tech_stack")
    list_filter = ("subdomain__domain",)
