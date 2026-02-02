#Intialize Django.
import os, django, subprocess,json
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backend.api.settings")
django.setup()
from backend.core.models import *


def takeover(domain):

    domain_obj = Domain.objects.get(hostname=domain)
    subdomains = domain_obj.subdomains.filter(cname__isnull=False).exclude(cname="")

    os.makedirs(f'/work/backend/core/scan/subdomain_takeover/data/{domain}', exist_ok=True)
    targets_file = f'/work/backend/core/scan/subdomain_takeover/data/{domain}/targets.txt'

    with open(targets_file, 'w') as f:
        for subdomain in subdomains:
            f.write(f'{subdomain}\n')

    templates_dir = f'/work/backend/core/scan/subdomain_takeover/templates'
    result_file = f'/work/backend/core/scan/subdomain_takeover/data/{domain}/results.json'

    cmd = [
        'nuclei', '-l', targets_file,
            '-t', templates_dir,
            '-j',
            '-o', result_file,
           ]
    import subprocess
    subprocess.run(cmd, text=True, capture_output=True)

    #Save the results to the database.

    import json
    from django.db import transaction

    with open(result_file, 'r') as file:
        for line in file:
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)

                template_id = data.get('template-id')
                host = data.get('host')

                info = data.get('info', {})
                severity = info.get('severity', 'unknown')

                extracted = data.get('extracted-results', [])
                if extracted and isinstance(extracted, list):
                    target_val = extracted[0]
                else:
                    target_val = data.get('matched-at', host)


                with transaction.atomic():
                    try:
                        subdomain_obj = Subdomain.objects.get(hostname=host)

                        obj, created = SubdomainTakeover.objects.update_or_create(
                            subdomain=subdomain_obj,
                            type=template_id,
                            defaults={
                                "severity": severity,
                                "target": target_val
                            }
                        )

                    except Subdomain.DoesNotExist:
                        print(f"[SKIP] Host {host} not found in Subdomain table.")

            except json.JSONDecodeError:
                print(f"Error decoding JSON line: {line[:50]}...")
            except Exception as e:
                print(f"Error processing line: {str(e)}")