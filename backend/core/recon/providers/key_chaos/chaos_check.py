import requests
import os

CHAOS_KEY = os.getenv("CHAOS_KEY")
url = "https://dns.projectdiscovery.io/dns"

def check():

    if not CHAOS_KEY:
        return -1

    headers = {"Authorization": CHAOS_KEY}

    try:
        response = requests.get(url, headers=headers)

        if response.status_code in (400, 401):
            return -1

    except Exception:
        return -1

    return 0