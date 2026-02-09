#Intialize Django.
import os, django, subprocess,json
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backend.api.settings")
django.setup()
from backend.core.models import *
from backend.core.scan.notify.notify import notify_discord

def takeover(domain):

    domain_obj = Domain.objects.get(hostname=domain)
    subdomains = domain_obj.subdomains.filter(cname__isnull=False).exclude(cname="")

    out_dir = f'/work/backend/core/scan/output/{domain}'
    os.makedirs(out_dir, exist_ok=True)
    targets_file = f'{out_dir}/takeover_candidates.txt'

    with open(targets_file, 'w') as f:
        for subdomain in subdomains:
            f.write(f'{subdomain}\n')

    templates_dir = f'/work/backend/core/scan/templates/takeover'
    result_file = f'{out_dir}/takeover.json'

    cmd = [
        'nuclei', '-l', targets_file,
            '-t', templates_dir,
            '-j',
            '-o', result_file,
           ]

    print(f"[*] Started Scanning for subdomain takeover on {domain}")
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
                host = data.get('host')

                extracted = data.get('extracted-results', [])
                if extracted and isinstance(extracted, list):
                    target_val = extracted[0]
                else:
                    target_val = data.get('matched-at', host)

                with transaction.atomic():
                    try:
                        subdomain_obj = Subdomain.objects.get(hostname=host)

                        Vulnerability.objects.update_or_create(
                            subdomain=subdomain_obj,
                            vuln_location=target_val,
                            defaults={
                                "vuln_severity": Vulnerability.Severity.HIGH,
                                "vuln_name" : template_id,
                                "vuln_type": "Subdomain Takeover"
                            }
                        )
                        message = f"[+] Subdomain Takeover type {template_id} on {target_val}"
                        print(message)
                        notify_discord(message)
                    except Subdomain.DoesNotExist:
                        print(f"[SKIP] Host {host} not found in Subdomain table.")

            except json.JSONDecodeError:
                print(f"Error decoding JSON line: {line[:50]}...")
            except Exception as e:
                print(f"Error processing line: {str(e)}")

    print(f"[+] Finished Scanning for subdomain takeover on {domain}")
