import os, django, requests, subprocess
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backend.websploit.settings")
django.setup()
from backend.core.models import *

vstotal_key = os.getenv("VIRUSTOTAL_KEY")


def fetch_virusl_total(subdomain):
    """
    Takes a subdomain & Gets urls from VirusTotal and saves it to the database.
    Returns the length of the found URLs.
    """

    url = 'https://www.virustotal.com/vtapi/v2/domain/report'
    params = {
        'apikey': f'{vstotal_key}',
        'domain': f'{subdomain}'
    }

    response = requests.get(url, params=params)
    data = response.json()

    urls_set = {item[0] for item in data.get('undetected_urls', [])}

    subdomain_obj = Subdomain.objects.get(hostname=subdomain)
    for u in urls_set:
        ArchivedURLs.objects.update_or_create(
            subdomain=subdomain_obj,
            url=u,
            defaults={
                "source":"VIRUS_TOTAL"
            }
        )

    return len(urls_set)


def get_archived_urls(subdomain):
    print(f"[*] Fetching archived urls for {subdomain}")
    print(f"[+] VirusTotal: {fetch_virusl_total(subdomain)}")
    print(f"[+] Done archived urls for {subdomain}")

