import requests
import os, django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backend.api.settings")
django.setup()
from backend.core.models import *
from backend.core.utilities.enum import load_urls_for_mining, heuristic, parse_headers
from urllib.parse import urlparse

def extract_parameters(url, auth_headers=None):
    """
    Takes a domain and extracts parameters from <input> and <script> and saves to the db.
    The target must be crawled first.
    """
    #Load target URLs.
    domain = urlparse(url).hostname
    urls_file = f'/work/backend/core/output/{domain}/htmlurls.txt'
    load_urls_for_mining(url, urls_file)

    params = list()
    urls = set()

    print(f"[*] Started extracting parameters for {url}")

    #Extract the parameters.
    if auth_headers:
        h = parse_headers(auth_headers)
    else:
        h = dict()

    h['User-Agent'] = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36'
    with open(urls_file, 'r') as file:
        for line in file:
            line = line.strip()
            urls.add(line)

    for i in urls:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        res = requests.get(i, headers=h, verify=False)
        p = heuristic(res)
        params.extend(p)

    #Save to the database
    web_app = WebApplication.objects.get(url=url)
    endpoint, _ = EndPoint.objects.get_or_create(
        web_app=web_app,
        path='/web-sploit-reserved-neralp',
    )

    for i in params:
        Parameter.objects.update_or_create(
            endpoint=endpoint,
            key=i,
            defaults={
                "value":"EXTRACTED",
            }
        )

    print(f"[+] Done extracting parameters for {url}")
