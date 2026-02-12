from django.db import models


class Target(models.Model):
    name = models.CharField(max_length=1000, unique=True)
    platform = models.CharField(max_length=1000, null=True, blank=True)
    program_url = models.CharField(max_length=1000, null=True, blank=True)

    def __str__(self):
        return self.name


class Domain(models.Model):
    target = models.ForeignKey(Target, on_delete=models.CASCADE, related_name="domains")
    hostname = models.CharField(max_length=1000, unique=True)

    def __str__(self):
        return self.hostname

class Subdomain(models.Model):
    domain = models.ForeignKey(Domain, on_delete=models.CASCADE, related_name="subdomains")
    hostname = models.CharField(max_length=1000, unique=True)
    cname = models.CharField(max_length=1000, null=True, blank=True)
    ip = models.CharField(max_length=100, null=True, blank=True)
    is_alive = models.BooleanField(default=False)

    def __str__(self):
        return self.hostname


class WebApplication(models.Model):
    subdomain = models.ForeignKey(Subdomain, on_delete=models.CASCADE, related_name="webapps")
    status_code = models.IntegerField(null=True, blank=True)
    url = models.CharField(max_length=1000,unique=True)
    content_length = models.IntegerField(null=True, blank=True)
    tech_stack = models.JSONField(default=list,null=True, blank=True)
    location = models.CharField(max_length=1000,null=True, blank=True)
    title = models.CharField(max_length=1000,null=True, blank=True)

    def __str__(self):
        return self.url


class Vulnerability(models.Model):
    subdomain = models.ForeignKey(Subdomain, on_delete=models.CASCADE, related_name="vulnerabilities", null=True, blank=True)
    url = models.ForeignKey(WebApplication, on_delete=models.CASCADE, related_name="vulnerabilities", null=True, blank=True)
    name = models.CharField(max_length=1000)
    location = models.CharField(max_length=1000)
    severity = models.CharField(max_length=1000)
    type = models.CharField(max_length=1000)

    class Meta:
        unique_together = ("name", "location")











class URL(models.Model):
    subdomain = models.ForeignKey(Subdomain, on_delete=models.CASCADE, related_name="URL")
    endpoint = models.CharField(max_length=1000, null=True, blank=True)
    status_code = models.IntegerField(null=True, blank=True)
    content_type = models.CharField(max_length=1000, null=True, blank=True)
    location = models.CharField(max_length=1000, null=True, blank=True)

    class Meta:
        unique_together = ("subdomain", "endpoint")

class Parameter(models.Model):
    subdomain = models.ForeignKey(Subdomain, on_delete=models.CASCADE, related_name="param")
    key = models.CharField(max_length=1000, null=True, blank=True)
    value = models.CharField(max_length=1000, null=True, blank=True)

    class Meta:
        unique_together = ("subdomain", "key")

class ArchivedURLs(models.Model):
    subdomain = models.ForeignKey(Subdomain, on_delete=models.CASCADE, related_name="ArchivedUrls")
    url = models.CharField(max_length=1000, null=True, blank=True)
    source = models.CharField(max_length=300, null=True, blank=True)

    class Meta:
        unique_together = ("subdomain", "url")


class JS_URLs(models.Model):
    subdomain = models.ForeignKey(Subdomain, on_delete=models.CASCADE, related_name="js_urls")
    url = models.CharField(max_length=1000, null=True, blank=True)
    file_name = models.CharField(max_length=1000, null=True, blank=True)

    class Meta:
        unique_together = ("subdomain", "url")