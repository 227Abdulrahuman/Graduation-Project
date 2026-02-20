import os, django, subprocess, json
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backend.api.settings")
django.setup()
from backend.core.models import *
from urllib.parse import urlparse
from backend.core.scan.notify.notify import notify_discord
from backend.core.utilities.loaders import load_html_urls_to_set, load_parameters_to_set
from django.db.models import CharField
from django.db.models.functions import Cast

# Casts the JSON to text, then searches for "php" case-insensitively
php_apps = WebApplication.objects.annotate(
    tech_text=Cast('tech_stack', output_field=CharField())
).filter(tech_text__icontains='php')

# To see the URLs and their specific tech stack
for app in php_apps:

    from backend.core.enum.crawler import crawl
    crawl(app.url)

    from backend.core.enum.parameter_discovery import extract_parameters
    extract_parameters(app.url)

    from backend.core.scan.XSS.xss import xss_scan


    xss_scan(app.url)