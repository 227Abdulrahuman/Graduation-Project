import json
import os, django, subprocess
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backend.websploit.settings")
django.setup()
from backend.core.models import *


def dns_recon(domain):
    domain_obj = Domain.objects.get(hostname=domain)

    #Get the cnames and IPs for live subdomains.
    output_file = f"/work/backend/core/output/{domain}/dns_recon.json"
    live_file = f"/work/backend/core/output/{domain}/live_subdomains.txt"

    cmd = [
        'dnsx', '-l', live_file,
        '-a', '-cname',
        '-silent', '-nc', '-resp',
        '-j', '-o', output_file
    ]

    print(f"\n[*] Starting DNS enumeration for {domain}")
    subprocess.run(cmd, text=True, capture_output=True)

    with open(output_file, 'r') as file:
        for line in file:
            line = line.strip()

            if not line:
                continue

            try:
                data = json.loads(line)
                Subdomain.objects.update_or_create(
                    domain=domain_obj,
                    hostname=data.get('host'),
                    defaults={
                        "is_alive": True,
                        "cname": data.get('cname')[-1] if data.get('cname') else None,
                        "ip": data.get('a')[0] if data.get('a') else None,
                    }
                )
            except Exception:
                pass

    print(f"[+] Finished DNS enumeration for {domain}")
