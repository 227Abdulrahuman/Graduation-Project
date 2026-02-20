#Intialize Django.
import os, django, subprocess,json
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backend.api.settings")
django.setup()
from backend.core.models import *
from backend.core.scan.notify.notify import notify_discord

def information_disclosure_scan(domain):

    out_dir = f'/work/backend/core/output/{domain}'
    os.makedirs(out_dir, exist_ok=True)
    targets_file = f'{out_dir}/urls.txt'

    templates_dir = f'/work/backend/core/scan/templates/disclosures'
    result_file = f'{out_dir}/disclosures.json'

    cmd = [
        'nuclei', '-l', targets_file,
            '-t', templates_dir,
            '-j',
            '-o', result_file,
           ]

    print(f"[*] Started Scanning for Information Disclosure on {domain}")
    subprocess.run(cmd, text=True, capture_output=True)

    from django.db import transaction
    with open(result_file, 'r') as file:
        for line in file:
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)

                template_id = data.get('template-id')
                url = data.get('url')
                web_app = WebApplication.objects.get(url=url.strip('/'))
                severity = data.get('info')['severity']

                with transaction.atomic():

                    Vulnerability.objects.update_or_create(
                        web_app=web_app,
                        location=url,
                        defaults={
                            "severity": severity,
                            "name" : template_id,
                            "type": "Information Disclosure"
                        }
                    )
                    message = f"[+] Found {template_id} on {url}"
                    print(message)
                    notify_discord(message)

            except Exception as e:
                print(f"Error processing line: {str(e)}")

    print(f"[+] Finished Scanning for Information Disclosure on {domain}")
