
#Intialize Django.
import os, django, subprocess,json
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backend.api.settings")
django.setup()
from backend.core.models import *


def web_fingerprint(domain):
    output_file = f"/work/backend/core/recon/output/{domain}/http.json"
    live_file = f"/work/backend/core/recon/output/{domain}/live.txt"

    print(f"[+] Starting Web Fingerprinting for {domain}")

    cmd = [
        'httpx', '-l', live_file,
        '-nc', '-silent',
        '-sc', '-title', '-location', '-td', '-cl',
        '-j', '-o', output_file,
    ]
    subprocess.run(cmd, text=True, capture_output=True)

    with open(output_file, 'r') as file:
        for line in file:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)

                url = data.get('url')
                host_name = data.get('input')
                status_code = data.get('status_code')
                content_length = data.get('content_length')
                tech = data.get('tech')
                title = data.get('title')
                location = data.get('location')

                subdomain_obj = Subdomain.objects.get(hostname=host_name)
                HTTPX.objects.update_or_create(
                    subdomain=subdomain_obj,
                    url=url,
                    defaults={
                        "status_code": status_code,
                        "content_length": content_length,
                        "tech": tech,
                        "title": title,
                        "location": location,
                    }
                )
            except Exception:
                pass

    print(f"[+] Done Web Fingerprinting for {domain}")