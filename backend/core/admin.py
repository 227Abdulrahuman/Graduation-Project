from django.contrib import admin
from . import models

admin.site.register(models.Domain)
admin.site.register(models.Company)

@admin.register(models.Subdomain)
class SubdomainAdmin(admin.ModelAdmin):
    list_display = ("hostname", "ip", "cname", "is_alive")
    list_filter = ("domain",)

@admin.register(models.WebFingerPrint)
class HTTPXAdmin(admin.ModelAdmin):
    list_display = ("url", "title", "status_code", "location", "tech", "content_length")
    list_filter = ("subdomain__domain",)

@admin.register(models.Port)
class NmapAdmin(admin.ModelAdmin):
    list_display = ('subdomain', 'port_number', 'state', 'service_name', 'product_name')
    list_filter = ("subdomain__domain",)

@admin.register(models.URL)
class URLAdmin(admin.ModelAdmin):
    list_display = ('endpoint', 'status_code', 'content_type', 'location')
    list_filter = ("subdomain__domain",)

@admin.register(models.Parameter)
class ParameterAdmin(admin.ModelAdmin):
    list_display = ('subdomain', 'key', 'value')
    list_filter = ("subdomain__domain",)

@admin.register(models.ArchivedURLs)
class ArchivedURLsAdmin(admin.ModelAdmin):
    list_display = ('subdomain', 'url', 'source')
    list_filter = ("subdomain__domain",)

@admin.register(models.JS_URLs)
class JSURLSADMIN(admin.ModelAdmin):
    list_display = ('subdomain', 'url', 'file_name')
    list_filter = ("subdomain__domain",)

@admin.register(models.Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = ('subdomain', 'vuln_location', 'vuln_name', 'vuln_type', 'vuln_severity')
    list_filter = ("subdomain__domain",)