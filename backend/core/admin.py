from django.contrib import admin
from . import models

@admin.register(models.Target)
class TargetAdmin(admin.ModelAdmin):
    list_display = ('name', 'type', 'program_url')

@admin.register(models.Domain)
class DomainAdmin(admin.ModelAdmin):
    list_display = ('hostname', 'target')
    list_filter = ('target',)

@admin.register(models.Subdomain)
class SubdomainAdmin(admin.ModelAdmin):
    list_display = ("hostname", "ip", "cname", "is_alive")
    list_filter = ("domain",)

@admin.register(models.WebApplication)
class WebAppAdmin(admin.ModelAdmin):
    list_display = ("url", "status_code", "title", "content_length", "tech_stack")
    list_filter = ("subdomain__domain",)

@admin.register(models.EndPoint)
class EndPointAdmin(admin.ModelAdmin):
    list_display = ('path', 'status_code', 'content_type', 'content_length', 'location_header')
    list_filter = ('web_app__url',)

@admin.register(models.Parameter)
class ParameterAdmin(admin.ModelAdmin):
    list_display = ('endpoint', 'key', 'value')
    list_filter = ("endpoint__web_app",)

@admin.register(models.ArchivedURLs)
class ArchivedURLsAdmin(admin.ModelAdmin):
    list_display = ('url', 'source')
    list_filter = ('subdomain__hostname',)

@admin.register(models.Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = ('name', 'location', 'severity', 'type')
    list_filter = ('subdomain__hostname','web_app__url')

