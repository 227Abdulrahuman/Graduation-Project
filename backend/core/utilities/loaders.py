import os, django, subprocess,json
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backend.api.settings")
django.setup()
from backend.core.models import *


def load_urls(domain):
    base_dir = f"/work/backend/core/output/{domain}"
    os.makedirs(base_dir, exist_ok=True)
    urls_file = base_dir + "/urls.txt"

    urls = WebApplication.objects.all()

    with open(urls_file, 'w') as file:
        for i in urls:
            file.write(f"{i.url}\n")