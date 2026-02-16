import os, django, subprocess, json
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backend.api.settings")
django.setup()
from backend.core.models import *
from urllib.parse import urlparse
from backend.core.scan.notify.notify import notify_discord
from backend.core.utilities.loaders import load_html_urls_to_set, load_parameters_to_set


def xss_scan(url, auth_headers=None):
    """
    Takes a subdomain and scans for reflected XSS by trying all parameters on all endpoints.
    """
    domain = urlparse(url).hostname
    output_dir = f'/work/backend/core/output/{domain}'
    os.makedirs(output_dir, exist_ok=True)


    urls_file = f"{output_dir}/xss_list.txt"

    urls = load_html_urls_to_set(url)
    params = load_parameters_to_set(url)

    # Create all URLS and parameters Combinations.
    with open(urls_file, 'w') as file:
        for u in urls:
            for p in params:
                file.write(f"{u}?{p}\n")

    out_file = f"{output_dir}/xss.json"

    cmd = ['ffuf', '-u', 'FUZZ',
          '-w', urls_file,
           '-mr', '(?i)"websploit"',
           '-H', 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36',
           '-o', out_file
           ]

    if auth_headers:
        for header in auth_headers:
            cmd.extend(["-H", header])

    print(f"[*] Starting XSS Scanning on {url}")
    subprocess.run(cmd, capture_output=True, text=True)


    web_app = WebApplication.objects.get(url=url)

    with open(out_file, 'r') as file:
        data = json.load(file)

    urls = [result['url'] for result in data.get('results', [])]

    for u in urls:
        Vulnerability.objects.update_or_create(
            web_app=web_app,
            name="Reflected XSS",
            location=u,

            defaults={
                "severity": "Medium",
                "type": "XSS"
            }
        )

        message = f"[+] Found RXSS at {u}"
        notify_discord(message)
        print(message)

    print(f"[+] Finished XSS Scanning on {url}")





