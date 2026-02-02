import requests
import os, django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backend.api.settings")
django.setup()
from backend.core.models import *
from backend.core.enum.utils import load_urls_for_mining, heuristic, parse_headers
from urllib.parse import urlparse

def parameter_extractor(url, auth_headers=None):
    """
    Takes a domain and extracts parameters from <input> and <script> and saves to the db.
    The target must be crawled first.
    """
    #Load target URLs.
    domain = urlparse(url).hostname
    urls_file = f'/work/backend/core/enum/output/{domain}/htmlurls.txt'
    load_urls_for_mining(domain)

    params = list()
    urls = set()

    print(f"[*] Started extracting parameters from {url}")

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
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # Optional: Suppress the warning noise
        res = requests.get(i, headers=h, verify=False)
        p = heuristic(res)
        params.extend(p)

    #Save to the database
    sub_obj = Subdomain.objects.get(hostname=domain)
    for i in params:
        Parameter.objects.update_or_create(
            subdomain=sub_obj,
            key=i,
            defaults={
                "value":"EXTRACTED",
            }
        )

    print(f"[+] Done extracting parameters from {url}")
