import os, django, subprocess,json
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backend.websploit.settings")
django.setup()
from backend.core.models import *
from backend.core.utilities.loaders import load_urls

def web_fingerprint(domain):
    output_file = f"/work/output/{domain}/web_fingerprint.json"
    live_file = f"/work/output/{domain}/live_subdomains.txt"

    cmd = [
        'httpx', '-l', live_file,
        '-nc', '-silent',
        '-sc', '-title', '-location', '-td', '-cl',
        '-j', '-o', output_file,
    ]

    print(f"\n[+] Starting Web Fingerprinting for {domain}")

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
                WebApplication.objects.update_or_create(
                    subdomain=subdomain_obj,
                    url=url,
                    defaults={
                        "status_code": status_code,
                        "content_length": content_length,
                        "tech_stack": tech,
                        "title": title,
                        "location": location,
                    }
                )
            except Exception:
                pass
    load_urls(domain)
    print(f"\n[+] Finished Web Fingerprinting for {domain}")