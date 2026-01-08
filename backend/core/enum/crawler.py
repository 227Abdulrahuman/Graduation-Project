import django, subprocess, os, shlex, json
from urllib.parse import urlparse

# Django Setup
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backend.api.settings")
django.setup()
from backend.core.models import *

def craw(url, auth_headers=None, logout=None):
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname: raise ValueError
    except:
        print(f"[-] Not a valid url {url}")
        return

    out_dir = f'/work/backend/core/enum/output/{hostname}'
    out_file = f'{out_dir}/katana.json'
    os.makedirs(out_dir, exist_ok=True)

    cmd = ["katana", "-u", url, "-j", "-o", out_file]

    if auth_headers:
        for header in auth_headers:
            cmd.extend(["-H", header])

    if logout:
        cmd.extend(["-cos", logout])

    print(f"[*] Executing: {shlex.join(cmd)}")

    # subprocess.run(cmd)

    subdomain_obj = Subdomain.objects.get(hostname=hostname)

    all_urls = set()
    with open(out_file, 'r') as file:

        for line in file:
            data = json.loads(line)

            url = data["request"].get("endpoint")

            try:
                urlparse(url)
                all_urls.add(url)
            except:
                pass

    #Decuttle the urls.

    urls_file = f"{out_dir}/urls.txt"
    with open(urls_file, 'w') as file:
        for i in all_urls:
            file.write(f"{i}\n")

    urls_file_decutled = f"{out_dir}/urls.decutled.txt"
    cmd = ['urless', '-i', urls_file, '-o', urls_file_decutled]
    subprocess.run(cmd, capture_output=True, text=True)

    valid_file = f"{out_dir}/valid.txt"




if __name__ == "__main__":
    craw("http://dvwa.com/", ["Cookie: PHPSESSID=bumnei3dpmho4rfdpl7gm2e1n0"], "logout.php")