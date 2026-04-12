import os, django, requests, subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backend.api.settings")
django.setup()
from backend.core.models import *
from pathlib import Path

urlscan_key = os.getenv("URLSCAN_KEY")
vstotal_key = os.getenv("VIRUSTOTALARCHIVE_KEY")
intlex_key = os.getenv("INTELX_API_KEY")


def init_waymore():
    config_dir = "/root/.config/waymore"
    os.makedirs(config_dir, exist_ok=True)

    config_file = Path(f"{config_dir}/config.yml")

    if not config_file.exists():
        with open(config_file, 'w') as file:
            file.write(f"""FILTER_CODE: 404
        FILTER_MIME: text/css,image/jpeg,image/jpg,image/png,image/svg+xml,image/gif,image/tiff,image/webp,image/bmp,image/vnd,image/x-icon,image/vnd.microsoft.icon,font/ttf,font/woff,font/woff2,font/x-woff2,font/x-woff,font/otf,audio/mpeg,audio/wav,audio/webm,audio/aac,audio/ogg,audio/wav,audio/webm,video/mp4,video/mpeg,video/webm,video/ogg,video/mp2t,video/webm,video/x-msvideo,video/x-flv,application/font-woff,application/font-woff2,application/x-font-woff,application/x-font-woff2,application/vnd.ms-fontobject,application/font-sfnt,application/vnd.android.package-archive,binary/octet-stream,application/octet-stream,application/pdf,application/x-font-ttf,application/x-font-otf,video/webm,video/3gpp,application/font-ttf,audio/mp3,audio/x-wav,image/pjpeg,audio/basic,application/font-otf,application/x-ms-application,application/x-msdownload,video/x-ms-wmv,image/x-png,video/quicktime,image/x-ms-bmp,font/opentype,application/x-font-opentype,application/x-woff,audio/aiff
        FILTER_URL: .css,.jpg,.jpeg,.png,.svg,.img,.gif,.mp4,.flv,.ogv,.webm,.webp,.mov,.mp3,.m4a,.m4p,.scss,.tif,.tiff,.ttf,.otf,.woff,.woff2,.bmp,.ico,.eot,.htc,.rtf,.swf,.image,/image,/img,/css,/wp-content,/wp-includes,/theme,/audio,/captcha,/font,node_modules,/jquery,/bootstrap
        URLSCAN_API_KEY:  {urlscan_key} 
        VIRUSTOTAL_API_KEY: {vstotal_key}
        CONTINUE_RESPONSES_IF_PIPED: True
        WEBHOOK_DISCORD: YOUR_WEBHOOK
        DEFAULT_OUTPUT_DIR:
        INTELX_API_KEY: {intlex_key}
        """)

def virus_total(subdomain):
    """
    Takes a subdomain & Gets urls from VirusTotal and saves it to the database.
    Returns the length of the found URLs.
    """

    out_dir = f'/work/backend/core/enum/output/{subdomain}'
    os.makedirs(out_dir, exist_ok=True)
    out_file = f'{out_dir}/key_virustotal.txt'

    url = 'https://www.virustotal.com/vtapi/v2/domain/report'
    params = {
        'apikey': f'{vstotal_key}',
        'domain': f'{subdomain}'
    }

    response = requests.get(url, params=params)
    data = response.json()

    urls_set = {item[0] for item in data.get('undetected_urls', [])}

    with open(out_file, 'w') as file:
        for u in urls_set:
            file.write(f"{u}\n")

    subdomain_obj = Subdomain.objects.get(hostname=subdomain)
    for u in urls_set:
        ArchivedURLs.objects.update_or_create(
            subdomain=subdomain_obj,
            url=u,
            defaults={
                "source":"VIRUS_TOTAL"
            }
        )

    return len(urls_set)

def url_scan(subdomain):
    """
    Takes a subdomain extracts urls from urlscan and saves the result to the database.
    returns the length of the found urls.
    """

    out_dir = f'/work/backend/core/enum/output/{subdomain}'
    os.makedirs(out_dir, exist_ok=True)
    out_file = f'{out_dir}/urlscan.txt'
    # waymore -i panasonic.com -mode U -nlf -fc 404 -xwm -xcc -xav -xix -xvt --no-subs -oU waymore.txt
    cmd = ['waymore', '-i', subdomain,
           '-mode', 'U',
           '-nlf', '-fc', '404',
           '-xwm', '-xcc', '-xav', '-xix', '-xvt',
           '--no-subs',
           '-oU', out_file
           ]

    result = subprocess.run(cmd, capture_output=True, text=True)

    sub_obj = Subdomain.objects.get(hostname=subdomain)

    if result.returncode != 0:
        print(f"[-] URLScan hit quota when searching for {subdomain}")
        return 0
    else:
        urls = set()
        with open(out_file, 'r') as file:
            for line in file:
                line = line.strip()
                p = urlparse(line)
                if p.hostname == subdomain:
                    urls.add(line)

        for u in urls:
            ArchivedURLs.objects.update_or_create(
                subdomain=sub_obj,
                url=u,
                defaults={
                    'source': 'URLSCAN'
                }
            )

        return len(urls)

def intelx(subdomain):

    out_dir = f'/work/backend/core/enum/output/{subdomain}'
    os.makedirs(out_dir, exist_ok=True)
    out_file = f'{out_dir}/intelix.txt'
    # waymore -i panasonic.com -mode U -nlf -fc 404 -xwm -xcc -xav -xus -xvt --no-subs -oU waymore.txt
    cmd = ['waymore', '-i', subdomain,
           '-mode', 'U',
           '-nlf', '-fc', '404',
           '-xwm','-xcc','-xav','-xus','-xvt',
           '--no-subs',
           '-oU', out_file
           ]
    result = subprocess.run(cmd, capture_output=True,text=True)

    sub_obj = Subdomain.objects.get(hostname=subdomain)

    if result.returncode != 0:
        print(f"[-] Intelix hit quota when searching for {subdomain}")
        return 0
    else:
        urls = set()
        with open(out_file,'r') as file:
            for line in file:
                line = line.strip()
                p = urlparse(line)
                if p.hostname == subdomain:
                    urls.add(line)

        for u in urls:
            ArchivedURLs.objects.update_or_create(
                subdomain=sub_obj,
                url=u,
                defaults={
                    'source': 'INTELIX'
                }
            )
        return len(urls)

def common_crawl(subdomain):

    out_dir = f'/work/backend/core/enum/output/{subdomain}'
    os.makedirs(out_dir, exist_ok=True)
    out_file = f'{out_dir}/common_crawl.txt'
    # waymore -i panasonic.com -mode U -nlf -fc 404 -xwm -xcc -xav -xix -xvt --no-subs -oU waymore.txt
    cmd = ['waymore', '-i', subdomain,
           '-mode', 'U',
           '-nlf', '-fc', '404',
           '-xwm', '-xus', '-xav', '-xix', '-xvt',
           '--no-subs',
           '-oU', out_file
           ]

    result = subprocess.run(cmd, capture_output=True, text=True)

    sub_obj = Subdomain.objects.get(hostname=subdomain)

    if result.returncode != 0:
        print(f"[-] CommonCrawl hit quota when searching for {subdomain}")
        return 0
    else:
        urls = set()
        with open(out_file, 'r') as file:
            for line in file:
                line = line.strip()
                p = urlparse(line)
                if p.hostname == subdomain:
                    urls.add(line)

        for u in urls:
            ArchivedURLs.objects.update_or_create(
                subdomain=sub_obj,
                url=u,
                defaults={
                    'source': 'COMMON_CRAWL'
                }
            )
        return len(urls)

def alien_vault(subdomain):

    out_dir = f'/work/backend/core/enum/output/{subdomain}'
    os.makedirs(out_dir, exist_ok=True)
    out_file = f'{out_dir}/alien_vault.txt'
    # waymore -i panasonic.com -mode U -nlf -fc 404 -xwm -xcc -xav -xix -xvt --no-subs -oU waymore.txt
    cmd = ['waymore', '-i', subdomain,
           '-mode', 'U',
           '-nlf', '-fc', '404',
           '-xwm', '-xcc', '-xus', '-xix', '-xvt',
           '--no-subs',
           '-oU', out_file
           ]

    result = subprocess.run(cmd, capture_output=True, text=True)

    sub_obj = Subdomain.objects.get(hostname=subdomain)

    if result.returncode != 0:
        print(f"[-] AlienVault hit quota when searching for {subdomain}")
        return 0
    else:
        urls = set()
        with open(out_file, 'r') as file:
            for line in file:
                line = line.strip()
                p = urlparse(line)
                if p.hostname == subdomain:
                    urls.add(line)

        for u in urls:
            ArchivedURLs.objects.update_or_create(
                subdomain=sub_obj,
                url=u,
                defaults={
                    'source': 'ALIEN_VAULT'
                }
            )
        return len(urls)

def get_from_source(name, func, subdomain):
    try:
        result = func(subdomain)
        print(f"[+] {name}: {result} URLs.")


    except Exception as e:
        print(f"[Error] {name}: {e}")


def get_archived_urls(subdomain):

    init_waymore()

    sources = [
        ("Virus Total", virus_total),
        ("Url Scan", url_scan),
        ("Intelix", intelx),
        ("Common Crawl", common_crawl),
        ("Alien Vault", alien_vault),
    ]

    with ThreadPoolExecutor(max_workers=len(sources)) as executor:
        futures = {
            executor.submit(get_from_source, name, func, subdomain): name
            for name, func in sources
        }
