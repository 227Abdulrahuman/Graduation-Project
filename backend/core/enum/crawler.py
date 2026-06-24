import django, subprocess, os, json
from urllib.parse import urlparse, parse_qs
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backend.websploit.settings")
django.setup()
from backend.core.models import *

def crawl(web_app_url, target_page, auth_headers=None, logout=None):

    """
    Crawl a target webapp, and saves endpoints and parameters to the database.
    """
    try:
        parsed = urlparse(web_app_url)
        hostname = parsed.hostname
    except:
        print(f"[-] Not a valid url {web_app_url}")
        return

    out_dir = f'/work/output/{hostname}'
    out_file = f'{out_dir}/crawler.json'
    os.makedirs(out_dir, exist_ok=True)

    cmd = ["katana", "-u", target_page, "-j", "-o", out_file]

    if auth_headers:
        for header in auth_headers:
            cmd.extend(["-H", header])

    if logout:
        cmd.extend(["-cos", logout])

    print(f"[*] Started Crawling {target_page}")

    subprocess.run(cmd, capture_output=True, text=True)

    web_app = WebApplication.objects.get(url=web_app_url)

    with open(out_file, 'r') as file:
        for line in file:
            try:
                data = json.loads(line.strip())
                req = data.get('request', {})
                res = data.get('response', {})
                headers = res.get('headers', {})

                path = req.get('endpoint')

                if not path or urlparse(path).hostname != hostname:
                    continue

                route = urlparse(path).path
                route = route.strip()

                if route == '':
                    route = '/'

                if not res.get('status_code'):
                    continue

                endpoint, _ = EndPoint.objects.get_or_create(
                    web_app=web_app,
                    path=route,
                    defaults={
                        'status_code': res.get('status_code'),
                        'content_type': headers.get('Content-Type'),
                        'content_length': headers.get('Content-Length', 0)
                    }
                )

                params_map = parse_qs(urlparse(path).query, keep_blank_values=True)
                for key, values in params_map.items():
                    Parameter.objects.update_or_create(
                        endpoint=endpoint,
                        key=key,
                        defaults={'value': values[0] if values else ''}
                    )
            except:
                pass

    print(f"[+] Finished Crawling {target_page}")
