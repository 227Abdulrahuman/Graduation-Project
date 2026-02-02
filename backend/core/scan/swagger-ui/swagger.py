import os, django, subprocess,json
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backend.api.settings")
django.setup()
from backend.core.models import *
domain = 'panasonic.com'

#Setup dir
data_dir = f"/work/backend/core/scan/swagger-ui/data/{domain}"
target_file = f"{data_dir}/targets.txt"
os.makedirs(data_dir, exist_ok=True)

#Get urls from database.
httpx_data = WebFingerPrint.objects.filter(subdomain__domain__hostname=domain)

#Save them to targets.txt
with open(target_file, 'w') as f:
    for i in httpx_data:
        f.write(f"{i.url}\n")






