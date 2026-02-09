#Intialize Django.
import os, django, subprocess,json
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backend.api.settings")
django.setup()
from backend.core.models import *
from backend.core.scan.notify.notify import notify_discord
from django.db import transaction


def git_exposures(domain):
    target_file = f'/work/backend/core/scan/output/{domain}/urls.txt'
    out_file = f'/work/backend/core/scan/output/{domain}/git_exposures.json'
    templates_dir = '/work/backend/core/scan/templates/git/'

    cmd = ['nuclei', '-l', target_file,
           '-t', templates_dir,
           '-bs', str(200),
           '-j','-o', out_file
           ]

    print(f"[*] Started Scanning for Git Exposures on {domain}")
    subprocess.run(cmd, capture_output=True, text=True)

    with open(out_file, 'r') as file:
        for line in file:
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)

                template_id = data.get('template-id')
                host = data.get('host')


                target_val = data.get('matched-at', host)

                with transaction.atomic():
                    try:
                        subdomain_obj = Subdomain.objects.get(hostname=host)

                        Vulnerability.objects.update_or_create(
                            subdomain=subdomain_obj,
                            vuln_location=target_val,
                            defaults={
                                "vuln_severity": Vulnerability.Severity.LOW,
                                "vuln_name": template_id,
                                "vuln_type": "Git Exposures"
                            }
                        )
                        message = f"[+] Git Exposures: type {template_id} on {target_val}"
                        print(message)
                        notify_discord(message)
                    except Subdomain.DoesNotExist:
                        print(f"[SKIP] Host {host} not found in Subdomain table.")

            except json.JSONDecodeError:
                print(f"Error decoding JSON line: {line[:50]}...")
            except Exception as e:
                print(f"Error processing line: {str(e)}")

    print(f"[+] Finished Scanning for git exposures on {domain}")
    pass