import requests
import os

key = os.getenv("DIGITALYAMA_KEY")
url = "https://api.digitalyama.com/subdomain_finder"

def check():

    if not key:
        return -1

    headers = {"x-api-key": key}

    try:
        response = requests.get(url, headers=headers)

        if response.status_code in (403, 401):
            return -1

    except Exception:
        return -1

    return 0