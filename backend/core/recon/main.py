from backend.core.recon.passive_subdomains_enum import passive_enum
from backend.core.recon.llm_permutations import generate_permutations
from backend.core.recon.subdomains_bruteforce import bruteforce
from backend.core.utilities.load_subdomains import load_subdomains
from backend.core.models import *


def recon_pipline(domain):
    print("###############################################")
    print(f"[*] Starting full recon pipline for {domain}")
    print("###############################################")

    passive_enum(domain)

    print(f"[*] Generating LLM Permutations for {domain}")
    generate_permutations(domain)
    print(f"[+] Done Generating LLM Permutations for {domain}")

    print(f"[*] Bruteforce permutations for {domain}")
    perm_file = f"/work/backend/core/recon/output/{domain}/permutations.txt"
    live_file = f"/work/backend/core/recon/output/{domain}/permutations.live.txt"
    bruteforce(perm_file,live_file)

    # Insert the results into the database
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

    print(f"[+] Found {len(live_subdomains)} live subdomains from LLM permutations for {domain}")

    all_file = f"/work/backend/core/recon/output/{domain}/all_live.txt"
    load_subdomains(domain, all_file)

    with open(all_file, 'r') as fp:
        line_count = sum(1 for line in fp)

    print(f"Found {line_count} total live subdomains for {domain}")

    print("###############################################")
    print(f"[+] DONE full recon pipline for {domain}")
    print("###############################################")


