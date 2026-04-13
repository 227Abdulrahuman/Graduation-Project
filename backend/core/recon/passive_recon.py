#import providers
from backend.core.recon.providers.key_virustotal.virustotal_scrap import scrap as virustotal
from backend.core.recon.providers.c99.c99_scrap import scrap as c99
from backend.core.recon.providers.securitytrails_web.securitytrailsweb_scrap import scrap as securitytrailsweb
from backend.core.recon.providers.key_chaos.chaos_scrap import scrap as chaos
from backend.core.recon.providers.key_shodan.shodan_scraper import scrap as shodan
from backend.core.recon.providers.key_digitalyama.digitalyama_scrap import scrap as digitalyama
from backend.core.recon.providers.subfinder.subfinder_scrap import scrap as subfinder

#Connect to Django
import os, django, subprocess
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backend.websploit.settings")
django.setup()
from concurrent.futures import ThreadPoolExecutor, as_completed
from backend.core.models import *

def run_provider(name, func, domain):
    """
    Gets subdomains from a single provider.
    """
    try:
        result = func(domain)

        if result == {-1}:
            print(f"[-] {name} ERROR.")
            return {-1}

        print(f"[+] {name}: {len(result)} subdomains.")

        return result

    except Exception as e:
        print(f"[Error] {name}: {e}")

def fetch_subdomains(domain):
    """
    Enumerates Subdomains from passive sources and saves the result to the database.
    """
    print(f"\n[*] Starting passive subdomains enumeration for {domain}")

    base_dir = f"/work/output/{domain}"
    os.makedirs(base_dir, exist_ok=True)
    subs_file = base_dir + "/passive_subdomains.txt"
    live_file = base_dir + "/live_subdomains.txt"
    all_subs = set()
    all_subs.add(domain)

    scrapers = [
        ("VirusTotal", virustotal),
        ("C99", c99),
        ("securityTrailsWeb", securitytrailsweb),
        ("key_chaos",chaos),
        ("key_shodan", shodan),
        ("key_digitalyama", digitalyama),
        ("subfinder", subfinder),
    ]

    #Run passive providers.
    with ThreadPoolExecutor(max_workers=len(scrapers)) as executor:
        futures = {
            executor.submit(run_provider, name, func, domain): name
            for name, func in scrapers
        }

        for future in as_completed(futures):
            result = future.result()

            if result != {-1} and result is not None:
                all_subs.update(result)


    with open(subs_file, "w") as f:
        for sub in all_subs:
            f.write(f"{sub}\n")


    #Resolve live subdomains.
    print(f"\n[*] Resolving live subdomains for {domain}")
    resolvers_file = f"/work/resources/resolvers/resolvers.txt"
    cmd = ['puredns', 'resolve', subs_file, '-r', resolvers_file, '-w', live_file]
    subprocess.run(cmd, text=True, capture_output=True)

    with open(live_file) as f:
        lines = sorted(set(line.strip() for line in f if line.strip()))
    with open(live_file, "w") as f:
        for line in lines:
            f.write(line + "\n")
    print(f"[+] Found {len(lines)} live subdomains for {domain}")

    #Insert the results into the database
    with open(live_file) as f:
        live_subdomains = set(line.strip() for line in f if line.strip())
    domain_obj = Domain.objects.get(hostname=domain)
    for sub in live_subdomains:
        is_alive = True
        Subdomain.objects.update_or_create(
            domain=domain_obj,
            hostname=sub,
            defaults={"is_alive": is_alive},
        )
    print(f"[+] Finished passive subdomains enumeration for {domain}")