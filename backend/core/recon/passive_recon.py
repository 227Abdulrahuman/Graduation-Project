#import providers
from backend.core.recon.providers.subfinder.subfinder import scrap as subfinder
from backend.core.recon.providers.virustotal.virustotal import scrap as virustotal
from backend.core.recon.providers.c99.c99 import scrap as c99
from backend.core.recon.providers.securitytrails_web.securitytrailsweb import scrap as securitytrailsweb
from backend.core.recon.providers.bevigil.bevigil import scrap as bevigil
from backend.core.recon.providers.chaos.chaos import scrap as chaos
from backend.core.recon.providers.leakix.leakix import scrap as leakix
from backend.core.recon.providers.netlas.netlas import scrap as netlas
from backend.core.recon.providers.fullHunt.fullHunt import scrap as fullHunt
from backend.core.recon.providers.shodan.shodan import scrap as shodan
from backend.core.recon.providers.certspotter.certspotter import scrap as certspotter
from backend.core.recon.providers.digitalyama.digitalyama import scrap as digitalyama
from backend.core.recon.providers.pugrecon.pugrecon import scrap as pugrecon
from backend.core.recon.providers.dnsdumpster.dnsdumpster import scrap as dnsdumpster

#Connect to Django
import os, django, subprocess
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backend.api.settings")
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
            print(f"[-] {name} key expired.")
            return {-1}

        print(f"[+] {name}: {len(result)} subdomains.")

        return result

    except Exception as e:
        print(f"[Error] {name}: {e}")

def fetch_subdomains(domain):
    """
    Enumerates Subdomains from passive sources and saves the result to the database.
    """
    print(f"[*] Starting passive subdomains enumeration for {domain}")

    base_dir = f"/work/backend/core/output/{domain}"
    os.makedirs(base_dir, exist_ok=True)
    subs_file = base_dir + "/passive_subdomains.txt"
    live_file = base_dir + "/live_subdomains.txt"
    all_subs = set()

    scrapers = [
        ("VirusTotal", virustotal),
        ("C99", c99),
        ("Subfinder", subfinder),
        ("securityTrailsWeb", securitytrailsweb),
        ("bevigil", bevigil),
        ("chaos",chaos),
        ("leakix", leakix),
        ("netlas", netlas),
        ("fullHunt", fullHunt),
        # ("shodan", shodan),
        ("certspotter", certspotter),
        ("digitalyama", digitalyama),
        ("pugrecon", pugrecon),
        ("dnsdumpster", dnsdumpster),
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
    print(f"[*] Resolving live subdomains for {domain}")
    resolvers_file = f"/work/backend/core/recon/resources/resolvers/resolvers.txt"
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