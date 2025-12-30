from celery import shared_task
# from backend.core.recon.passive_subdomains_enum import passive_enum
# from backend.core.recon.dns_enum import dns_enum
# from backend.core.recon.web_fingerprinting import web_fingerprint
# from backend.core.scan.subdomain_takeover.takeover import takeover
#
# @shared_task
# def enum(domain):
#     try:
#         passive_enum(domain)
#     except Exception as e:
#         return f"Error during Passive enumeration: {str(e)}"
#
#     try:
#         dns_enum(domain)
#     except Exception as e:
#         return f"Error during DNS enumeration: {str(e)}"
#
#     try:
#         web_fingerprint(domain)
#     except Exception as e:
#         return f"Error during HTTP enumeration: {str(e)}"
#
#
# @shared_task
# def scan(domain):
#     print(f"[+] Start scanning for subdomain takeover for {domain}")
#     takeover(domain)
#     print(f"[*] Done scanning for subdomain takeover for {domain}")