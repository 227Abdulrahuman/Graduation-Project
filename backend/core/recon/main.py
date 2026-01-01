from backend.core.recon.passive_subdomains_enum import passive_enum
from backend.core.recon.llm_permutations import generate_permutations
from backend.core.recon.subdomains_bruteforce import bruteforce
from backend.core.utilities.load_subdomains import load_subdomains
from backend.core.recon.dns_enum import dns_enum
from backend.core.recon.web_fingerprinting import web_fingerprint
from backend.core.models import *
import subprocess


def recon_pipline(domain):
    print("###############################################")
    print(f"[*] Starting full recon pipline for {domain}")
    print("###############################################")

    passive_enum(domain)

    print(f"[*] Generating LLM Permutations for {domain}")
    generate_permutations(domain)
    perm_file = f"/work/backend/core/recon/output/{domain}/permutations.txt"
    with open(perm_file, 'r') as fp:
        line_count = sum(1 for line in fp)
    print(f"[+]Generating {line_count} Permutations for {domain}")

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

    allFile = f"/work/backend/core/recon/output/{domain}/live.txt"
    subfile = f"/work/backend/core/recon/output/{domain}/permutations.live.txt"

    proc = subprocess.run(f"cat {subfile} | anew {allFile}", shell=True, capture_output=True, text=True)
    new_count = 0

    diff_file = f"/work/backend/core/recon/output/{domain}/diff.txt"

    with open(diff_file, 'w') as df:
        for i in proc.stdout.splitlines():
            new_count += 1
            df.write(f"{i.strip()}\n")
            print(i.strip())

    print(f"Found {new_count} new subdomains from smart bruteforce.")


    with open(allFile, 'r') as fp:
        line_count = sum(1 for line in fp)

    print(f"Found {line_count} total live subdomains for {domain}")

    print(f"[*] Starting DNS Recon on {domain}")
    dns_enum(domain)
    print(f"[+] Done DNS Recon on {domain}")

    print(f"[*] Starting Web Recon on {domain}")
    web_fingerprint(domain)
    print(f"[+] Done Web Recon on {domain}")


    print("###############################################")
    print(f"[+] DONE full recon pipline for {domain}")
    print("###############################################")


