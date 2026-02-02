import subprocess, json
from urllib.parse import urlparse
import os, django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backend.api.settings")
django.setup()
from backend.core.models import *
from pathlib import Path



def download_js(subdomain, auth_headers=None):
    """
    Downloads the JS files for a subdomain using curl.
    """
    out_dir = os.path.join('/work/backend/core/enum/output', subdomain, 'js')
    os.makedirs(out_dir, exist_ok=True)

    sub_obj = Subdomain.objects.get(hostname=subdomain)
    urls = URL.objects.filter(
        subdomain=sub_obj,
        content_type__icontains='javascript'
    )

    for url_obj in urls:
        link = url_obj.endpoint

        parsed_path = urlparse(link).path
        filename = os.path.basename(parsed_path)

        if not filename:
            filename = "index.js"

        file_path = os.path.join(out_dir, filename)

        cmd = ['curl', '-o', file_path, '-k']

        if auth_headers:
            for header in auth_headers:
                cmd.extend(["-H", header])

        cmd.append(link)

        print(f"Downloading: {link}")

        try:
            subprocess.run(cmd, capture_output=True, text=True, check=True)
        except subprocess.CalledProcessError as e:
            print(f"Failed to download {link}: {e.stderr}")
    pass

def extract_urls(subdomain):
    """
    Extracts the Endpoints from JS files for a subdomain.
    """
    js_dir = Path(f"/work/backend/core/enum/output/{subdomain}/js")

    sub_obj = Subdomain.objects.get(hostname=subdomain)

    for js_file in js_dir.iterdir():
        cmd = ['jsluice', 'urls', js_file]

        print(f"[+] Extracting URLs from {js_file.stem}")
        proc = subprocess.run(cmd, capture_output=True, text=True)

        for line in proc.stdout.splitlines():
            line = json.loads(line)

            JS_URLs.objects.update_or_create(
                subdomain=sub_obj,
                url=line['url'],
                defaults= {
                    'file_name' : js_file.stem
                }
            )
    pass


def analys_js(subdomain, auth_headers=None):
    download_js(subdomain, auth_headers)
    extract_urls(subdomain)
