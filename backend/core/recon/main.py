from backend.core.recon.providers.key_chaos.chaos_check import check as chaos_check
from backend.core.recon.providers.key_digitalyama.digitalyama_check import check as digitalyama_check
from backend.core.recon.providers.key_shodan.shodan_check import check as shodan_check
from backend.core.recon.providers.securitytrails_web.securitytrailsweb_check import check as securitytrailsweb_check
from backend.core.recon.providers.key_virustotal.virustotal_check import check as virustotal_check


from backend.core.recon.passive_recon import fetch_subdomains
from backend.core.recon.dns_recon import dns_recon
from backend.core.recon.web_fingerprinting import web_fingerprint
from backend.core.recon.llm_permutations import generate_permutations


_KEY_CHECKS = {
    "virustotal":         virustotal_check,
    "key_chaos":          chaos_check,
    "key_shodan":         shodan_check,
    "key_digitalyama":    digitalyama_check,
    "securitytrails_web": securitytrailsweb_check,
}

def validate_api_keys(providers=None):

    if providers is not None:
        checks = [(name, func) for name, func in _KEY_CHECKS.items() if name in providers]
    else:
        checks = list(_KEY_CHECKS.items())

    invalid_providers = []

    for name, check_func in checks:
        try:

            result = check_func()

            if result == -1:
                invalid_providers.append(name)

        except Exception as e:
            print(f"[Error] Failed while checking key for {name}: {e}")
            invalid_providers.append(name)

    return invalid_providers


def recon(domain, chunk_size=None, multiplicity=3, providers=None):
    print(f"[*] Starting recon pipeline for {domain}")

    if providers is not None:
        print(f"[*] Selected providers: {', '.join(providers)}")

    print("[*] Validating API keys for paid providers...")
    invalid_keys = validate_api_keys(providers)

    if invalid_keys:
        print(f"[-] Pipeline aborted! Invalid API keys detected for: {', '.join(invalid_keys)}")
        return invalid_keys

    print("[+] All API keys are valid.")

    print()
    fetch_subdomains(domain, providers=providers)
    print()

    if chunk_size is not None:
        generate_permutations(domain, chunk_size, multiplicity=multiplicity)
        print()

    dns_recon(domain)
    print()
    web_fingerprint(domain)
    print()
    print(f"[+] Finished recon pipline for {domain}")

    return True
