import os, django, requests, subprocess
from urllib.parse import urlparse
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backend.api.settings")
django.setup()
from backend.core.models import *
from pathlib import Path


sub = "seikitoriatsukaiten.jp.eww.panasonic.com"

obj = Subdomain.objects.get(hostname=sub)

print(obj.hostname)
print(obj.ip)
print(obj.cname)