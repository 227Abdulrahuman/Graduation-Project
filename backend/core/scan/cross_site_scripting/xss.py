# import os, django, subprocess, json
# os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backend.api.settings")
# django.setup()
# from backend.core.models import *
#
# from backend.core.scan.utils import load_html_urls_to_set, load_parameters_to_set
#
#
# def xss_scan(subdomain, auth_headers=None):
#     """
#     Takes a subdomain and scans for reflected XSS by trying all parameters on all endpoints.
#     """
#
#     output_dir = f'/work/backend/core/scan/output/{subdomain}/xss'
#     os.makedirs(output_dir, exist_ok=True)
#
#
#     urls_file = f"{output_dir}/urls.txt"
#
#     urls = load_html_urls_to_set(subdomain)
#     params = load_parameters_to_set(subdomain)
#
#     # Create all URLS and parameters Combinations.
#     with open(urls_file, 'w') as file:
#         for u in urls:
#             for p in params:
#                 file.write(f"{u}?{p}\n")
#
#
#     # Testing Reflection with Nuclie
#     template_file = "/work/backend/core/scan/templates/xss.yaml"
#     out_file = f"{output_dir}/nuclie.json"
#
#     cmd = ['nuclei', '-l', urls_file,
#            '-dast', '-t', template_file,
#            '-j', '-o', out_file
#            ]
#
#     if auth_headers:
#         for header in auth_headers:
#             cmd.extend(["-H", header])
#
#     print(f"[*] Starting XSS Scanning on {subdomain}")
#     subprocess.run(cmd, capture_output=True, text=True)
#
#
#     sub_obj = Subdomain.objects.get(hostname=subdomain)
#     # #Parse JSON Result.
#     # with open(out_file, 'r') as file:
#     #     for line in file:
#     #         line = line.strip()
#     #         if not line:
#     #             continue
#     #
#     #         try:
#     #             data = json.loads(line)
#     #
#     #             vuln = data.get("matched-at")
#     #
#     #             if vuln:
#     #                 RXSS.objects.update_or_create(
#     #                     subdomain=sub_obj,
#     #                     vuln_endpoint=vuln
#     #                 )
#     #
#     #             print(f"[+] RXSS at {vuln}")
#     #
#     #         except:
#     #             print(f"[-] Error during XSS scanning for {subdomain} in parsing JSON")
#
#
#
#
