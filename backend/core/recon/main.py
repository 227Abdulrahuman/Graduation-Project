from backend.core.recon.passive_recon import fetch_subdomains
from backend.core.recon.dns_recon import dns_recon
from backend.core.recon.web_fingerprinting import web_fingerprint
from backend.core.recon.gemini_permutations import generate_permutations

def run_recon_pipeline(domain, chunk_size=None):
    print("###############################################")
    print(f"[*] Starting recon pipeline for {domain}")
    print("###############################################")

    print()
    fetch_subdomains(domain)
    print()
    dns_recon(domain)
    print()
    web_fingerprint(domain)
    print()

    if chunk_size is not None:
        generate_permutations(domain, chunk_size)
        print()

    print("###############################################")
    print(f"[+] Finished recon pipline for {domain}")
    print("###############################################")
