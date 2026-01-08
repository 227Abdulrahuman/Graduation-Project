from django.db import models



class Company(models.Model):
    name = models.CharField(max_length=10000, unique=True)

    def __str__(self):
        return self.name


class Domain(models.Model):
    company = models.ForeignKey(Company, on_delete=models.CASCADE, related_name="domains")
    hostname = models.CharField(max_length=10000, unique=True)

    def __str__(self):
        return self.hostname

class Subdomain(models.Model):
    domain = models.ForeignKey(Domain, on_delete=models.CASCADE, related_name="subdomains")
    is_alive = models.BooleanField(default=False)
    hostname = models.CharField(max_length=10000)
    cname = models.CharField(max_length=10000, null=True, blank=True)
    ip = models.CharField(max_length=10000, null=True, blank=True)

    class Meta:
        unique_together = ("domain", "hostname")

    def __str__(self):
        return self.hostname


class HTTPX(models.Model):
    subdomain = models.ForeignKey(Subdomain, on_delete=models.CASCADE, related_name="web_fingerprint")
    status_code = models.IntegerField(null=True, blank=True)
    url = models.CharField(max_length=10000,null=True, blank=True)
    content_length = models.IntegerField(null=True, blank=True)
    tech = models.JSONField(default=list,null=True, blank=True)
    location = models.CharField(max_length=10000,null=True, blank=True)
    title = models.CharField(max_length=10000,null=True, blank=True)

    class Meta:
        unique_together = ("subdomain", "url")

class SubdomainTakeover(models.Model):
    subdomain = models.ForeignKey(Subdomain, on_delete=models.CASCADE, related_name="subdomain_takeover")
    type = models.CharField(max_length=1000, null=True, blank=True)
    severity = models.CharField(max_length=1000, null=True, blank=True)
    target = models.JSONField(default=list,null=True, blank=True)

class Nmap(models.Model):
    subdomain = models.ForeignKey(Subdomain, on_delete=models.CASCADE, related_name="nmap")
    port_number = models.IntegerField(null=True,blank=True)
    state = models.CharField(max_length=1000, null=True, blank=True)
    service_name = models.CharField(max_length=1000, null=True, blank=True)
    product_name = models.CharField(max_length=1000, null=True, blank=True)

    class Meta:
        unique_together = ("subdomain", "port_number")

class Katana(models.Model):
    subdomain = models.ForeignKey(Subdomain, on_delete=models.CASCADE, related_name="katana")
    uri = models.CharField(max_length=1000, null=True, blank=True)

    class Meta:
        unique_together = ("subdomain", "uri")

class EndPoint(models.Model):
    subdomain = models.ForeignKey(Subdomain, on_delete=models.CASCADE, related_name="endpoint")
    path = models.CharField(max_length=1000, null=True, blank=True)
    status_code = models.IntegerField(null=True, blank=True)

    class Meta:
        unique_together = ("subdomain", "path")

class Parameter(models.Model):
    endpoint = models.ForeignKey(EndPoint, on_delete=models.CASCADE, related_name="parameter")
    key = models.CharField(max_length=1000, null=True, blank=True)
    value = models.CharField(max_length=1000, null=True, blank=True)

    class Meta:
        unique_together = ("key", "endpoint")