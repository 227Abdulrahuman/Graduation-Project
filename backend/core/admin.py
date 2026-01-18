from django.contrib import admin
from . import models
# Register your models here.

admin.site.register(models.Domain)
admin.site.register(models.Company)

@admin.register(models.Subdomain)
class SubdomainAdmin(admin.ModelAdmin):
    list_display = ("hostname","ip","cname","is_alive")

@admin.register(models.HTTPX)
class HTTPXAdmin(admin.ModelAdmin):
    list_display = ("url", "title", "status_code", "location", "tech", "content_length" )

@admin.register(models.SubdomainTakeover)
class SubdomainTakeoverAdmin(admin.ModelAdmin):
    list_display = ('subdomain', 'severity', 'type', 'target')

@admin.register(models.Nmap)
class NmapAdmin(admin.ModelAdmin):
    list_display = ('subdomain', 'port_number', 'state', 'service_name', 'product_name')

@admin.register(models.URL)
class URLAdmin(admin.ModelAdmin):
    list_display = ('endpoint', 'status_code', 'content_type', 'location')

@admin.register(models.Parameter)
class ParameterAdmin(admin.ModelAdmin):
    list_display = ('subdomain', 'key', 'value')

@admin.register(models.ArchivedURLs)
class ArchivedURLsAdmin(admin.ModelAdmin):
    list_display = ('subdomain', 'url', 'source')

@admin.register(models.RXSS)
class RXSSAdmin(admin.ModelAdmin):
    list_display = ('subdomain', 'vuln_endpoint')

