import django, subprocess, os, shlex, json
from urllib.parse import urlparse, parse_qsl, urlsplit
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backend.api.settings")
django.setup()
from backend.core.models import *

def crawl(url, auth_headers=None, logout=None):
    """
    Crawl a target webapp, and saves endpoints and parameters to the database.
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
    except:
        print(f"[-] Not a valid url {url}")
        return

    out_dir = f'/work/backend/core/output/{hostname}'
    out_file = f'{out_dir}/crawler.json'
    os.makedirs(out_dir, exist_ok=True)

    cmd = ["katana", "-u", url, "-j", "-o", out_file]

    if auth_headers:
        for header in auth_headers:
            cmd.extend(["-H", header])

    if logout:
        cmd.extend(["-cos", logout])

    print(f"[*] Started Crawling {url}")

    subprocess.run(cmd, capture_output=True, text=True)

    all_urls = set()
    with open(out_file, 'r') as file:

        for line in file:
            data = json.loads(line)

            u = data["request"].get("endpoint")

            try:
                p = urlparse(u)
                #Check if the crawled url belongs to our target.
                if p.hostname == hostname:
                    all_urls.add(u)
            except:
                pass


