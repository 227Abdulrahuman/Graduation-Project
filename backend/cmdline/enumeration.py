import sys
import os, django
from urllib.parse import urlparse

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backend.api.settings")
django.setup()
from backend.core.models import *


#Parse Input.
url = sys.argv[1]
subdomain = urlparse(url).hostname
headers = []

for i in range(2,len(sys.argv)):
    headers.append(sys.argv[i])


from backend.core.enum.crawler import crawl
from backend.core.enum.parameter_discovery import parameter_extractor
from backend.core.enum.js_analysis import analys_js
from backend.core.scan.cross_site_scripting.xss import xss_scan

crawl(url, headers)
parameter_extractor(url, headers)
xss_scan(subdomain, headers)
analys_js(subdomain,headers)
