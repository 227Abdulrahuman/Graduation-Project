import requests
import os

CHAOS_KEY =  os.getenv("CHAOS_KEY")
BASE_URL = "https://dns.projectdiscovery.io/dns"

def scrap(domain):
    headers = {"Authorization": CHAOS_KEY}
    url = f"{BASE_URL}/{domain}/subdomains"
    subdomains = set()
    try:
        response =  requests.get(url, headers=headers)

        subs = response.json()["subdomains"]
        for subdomain in subs:
            full_subdomain = f"{subdomain}.{domain}"

            #*.sub.example.com => sub.example.com
            if full_subdomain[0] == '*' and full_subdomain[1] == '.':
                full_subdomain = full_subdomain[2:]
            subdomains.add(full_subdomain)
    except Exception:
        subdomains = set()
    return subdomains
