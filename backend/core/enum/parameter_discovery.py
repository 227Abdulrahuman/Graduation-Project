import requests
from backend.core.utilities.declutter import declutter_urls
import os, django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backend.websploit.settings")
django.setup()
from backend.core.models import *
from backend.core.utilities.enum import heuristic, parse_headers
from urllib.parse import urlparse
from backend.core.utilities.loaders import load_html_urls_to_set

def extract_parameters(url, auth_headers=None, logout=None):
    """
    Takes a url and extracts parameters from <input> and <script> and saves to the db.
    The target must be crawled first.
    """
    print(f"[*] Started extracting parameters for {url}")


    #Load target URLs.
    urls = load_html_urls_to_set(url,logout=logout)
    urls = declutter_urls(urls)

    if auth_headers:
        h = parse_headers(auth_headers)
    else:
        h = dict()

    h['User-Agent'] = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36'

    web_app = WebApplication.objects.get(url=url)

    for i in urls:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        res = requests.get(i, headers=h, verify=False)
        params = heuristic(res)

        endpoint_path = urlparse(i).path
        endpoint = EndPoint.objects.get(web_app=web_app, path=endpoint_path)

        for param in params:
            Parameter.objects.update_or_create(
                endpoint=endpoint,
                key=param,
                defaults={
                    "value": "EXTRACTED",
                }
            )

    print(f"[+] Done extracting parameters for {url}")
