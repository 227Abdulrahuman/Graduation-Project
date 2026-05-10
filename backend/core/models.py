from django.db import models


class Target(models.Model):
    name = models.CharField(max_length=1000, unique=True)
    type = models.CharField(max_length=1000, null=True, blank=True)
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

class Port(models.Model):
    subdomain = models.ForeignKey(Subdomain, on_delete=models.CASCADE, related_name="ports")
    number = models.IntegerField(null=True, blank=True)
    service = models.CharField(max_length=1000, null=True, blank=True)

class WebApplication(models.Model):
    subdomain = models.ForeignKey(Subdomain, on_delete=models.CASCADE, related_name="webapps")
    status_code = models.IntegerField(null=True, blank=True)
    url = models.CharField(max_length=1000,unique=True)
    content_length = models.IntegerField(null=True, blank=True)
    tech_stack = models.JSONField(default=list,null=True, blank=True)
    location = models.CharField(max_length=1000,null=True, blank=True)
    title = models.CharField(max_length=1000,null=True, blank=True)
    analyzed = models.BooleanField(default=False)

    def __str__(self):
        return self.url

class EndPoint(models.Model):
    web_app = models.ForeignKey(WebApplication, on_delete=models.CASCADE, related_name="endpoint")
    path = models.CharField(max_length=1000, null=True, blank=True)
    status_code = models.IntegerField(null=True, blank=True)
    content_type = models.CharField(max_length=1000, null=True, blank=True)
    content_length = models.IntegerField(null=True, blank=True)
    location_header = models.CharField(max_length=1000, null=True, blank=True)

    class Meta:
        unique_together = ("web_app", "path")

    def __str__(self):
        return self.path

class Parameter(models.Model):
    endpoint = models.ForeignKey(EndPoint, on_delete=models.CASCADE, related_name="parameter")
    key = models.CharField(max_length=1000, null=True, blank=True)
    value = models.CharField(max_length=1000, null=True, blank=True)

    class Meta:
        unique_together = ("endpoint", "key")

class ArchivedURLs(models.Model):
    subdomain = models.ForeignKey(Subdomain, on_delete=models.CASCADE, related_name="ArchivedURLs")
    url = models.CharField(max_length=1000, null=True, blank=True)
    source = models.CharField(max_length=300, null=True, blank=True)

    class Meta:
        unique_together = ("subdomain", "url")


class Vulnerability(models.Model):
    web_app = models.ForeignKey(WebApplication, on_delete=models.CASCADE, related_name="vulnerabilities", null=True, blank=True)
    endpoint = models.ForeignKey(EndPoint, on_delete=models.CASCADE, related_name="endpoint", null=True, blank=True)
    parameter = models.ForeignKey(Parameter, on_delete=models.CASCADE, related_name="parameter", null=True, blank=True)
    name = models.CharField(max_length=1000)
    location = models.CharField(max_length=1000)
    severity = models.CharField(max_length=1000)
    type = models.CharField(max_length=1000)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=['name', 'web_app'],
                name='unique_name_per_webapp',
                condition=models.Q(web_app__isnull=False)
            ),
            models.UniqueConstraint(
                fields=['name', 'endpoint'],
                name='unique_name_per_endpoint',
                condition=models.Q(endpoint__isnull=False)
            ),
            models.UniqueConstraint(
                fields=['name', 'parameter'],
                name='unique_name_per_parameter',
                condition=models.Q(parameter__isnull=False)
            ),
        ]
