import os, requests


key = os.getenv("FULLHUNT_KEY")


def scrap(domain):
    url = f"https://fullhunt.io/api/v1/domain/{domain}/subdomains"
    headers = {
        "X-API-Key": key
    }

    response = requests.get(url, headers=headers)
    if 400 <= response.status_code < 500:
        return {-1}
    else:
        try:
            response = response.json()
            subdomains = set()
            for sub in response['hosts']:
                subdomains.add(sub)
            return subdomains
        except Exception:
            return set()
