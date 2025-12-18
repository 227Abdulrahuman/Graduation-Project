#import scrappers
from backend.core.recon.scrapers.subfinder.subfinder import scrap as subfinder
from backend.core.recon.scrapers.virustotal.virustotal import scrap as virustotal
from backend.core.recon.scrapers.c99.c99 import scrap as c99
from backend.core.recon.scrapers.securitytrails_web.securitytrailsweb import scrap as securitytrailsweb

#Intialize Django.
import os, django, subprocess
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backend.api.settings")
django.setup()
from concurrent.futures import ThreadPoolExecutor, as_completed
from backend.core.models import *


def run_scraper(name, func, domain):
    try:
        result = func(domain)

        if result == {-1}:
            print(f"[-] {name} key expired.")
            return

        print(f"[+] {name}: {len(result)} subdomains.")

        return result

    except Exception as e:
        print(f"[Error] {name}: {e}")

def passive_enum(domain):
    print(f"[+] Starting passive subdomains enumeration for {domain}")
    base_dir = f"/work/backend/core/recon/output/{domain}"
    os.makedirs(base_dir, exist_ok=True)
    subs_file = base_dir + "/subdomains.txt"
    live_file = base_dir + "/live.txt"
    all_subs = set()

    scrapers = [
        ("VirusTotal", virustotal),
        ("C99", c99),
        ("Subfinder", subfinder),
        ("securityTrailsWeb", securitytrailsweb),
    ]

    with ThreadPoolExecutor(max_workers=len(scrapers)) as executor:
        futures = {
            executor.submit(run_scraper, name, func, domain): name
            for name, func in scrapers
        }

        for future in as_completed(futures):
            result = future.result()

            if result != {-1}:
                all_subs.update(result)

    with open(subs_file, "w") as f:
        for sub in all_subs:
            f.write(f"{sub}\n")

    resolvers_file = f"/work/backend/core/recon/resources/resolvers/resolvers.txt"
    cmd = ['puredns', 'resolve', subs_file, '-r', resolvers_file, '-w', live_file]
    subprocess.run(cmd, text=True, capture_output=True)

    with open(live_file) as f:
        lines = sorted(set(line.strip() for line in f if line.strip()))
    with open(live_file, "w") as f:
        for line in lines:
            f.write(line + "\n")

    #     #Insert the results into the database
    with open(subs_file) as f:
         passive_subdomains = set(line.strip() for line in f if line.strip())
    with open(live_file) as f:
        live_subdomains = set(line.strip() for line in f if line.strip())
    domain_obj = Domain.objects.get(hostname=domain)
    for sub in passive_subdomains:
        is_alive = sub in live_subdomains
        Subdomain.objects.update_or_create(
            domain=domain_obj,
            hostname=sub,
            defaults={"is_alive": is_alive},
            )

    print(f"Found {len(lines)} live subdomains.")



