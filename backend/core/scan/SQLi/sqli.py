import os, django, subprocess, json
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backend.websploit.settings")
django.setup()
from backend.core.models import *
from urllib.parse import urlparse
from backend.core.scan.notify.notify import notify_discord

def sqli_scan(url, auth_headers=None):
    """
    Scans for error based SQL Injection.
    """
    domain = urlparse(url).hostname
    output_dir = f'/work/backend/core/output/{domain}'
    targets_file = f"{output_dir}/sqli_scan_targets.txt"

    out_file = f"{output_dir}/sqli.json"

    cmd = ['ffuf', '-u', 'FUZZ',
          '-w', targets_file,
           '-mt', '>90000', '-mc', '500-599', '-mr', '(?i)(sql syntax|invalid identifier|syntax error|Incorrect syntax)', '-r',
           '-H', 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36',
           '-o', out_file
           ]

    if auth_headers:
        for header in auth_headers:
            cmd.extend(["-H", header])

    print(f"[*] Starting SQL Injection Scanning on {url}")
    subprocess.run(cmd, capture_output=True, text=True)



    with open(out_file, 'r') as file:
        data = json.load(file)

    urls = [result['url'] for result in data.get('results', [])]

    web_app = WebApplication.objects.get(url=url)

    for u in urls:
        path = urlparse(u).path
        endpoint = EndPoint.objects.get(web_app=web_app,path=path)

        parameter_value = urlparse(u).query.split("=")[0]

        parameter_obj = Parameter.objects.get(endpoint=endpoint, key=parameter_value)

        Vulnerability.objects.update_or_create(
            parameter=parameter_obj,
            name="SQL Injection",

            defaults={
                "location": u,
                "severity": "Critical",
                "type": "Server Side"
            }
        )

        message = f"[+] Found SQL Injection at {u}"
        notify_discord(message)
        print(message)

    print(f"[+] Finished SQL Injection Scanning on {url}")





