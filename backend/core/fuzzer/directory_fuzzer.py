import subprocess
import os
import json
from urllib.parse import urlparse

from backend.core.models import WebApplication, EndPoint


def directory_fuzz(url, wordlist_path):
    domain = urlparse(url).hostname
    output_dir = f'/work/output/{domain}'
    out_file = f"{output_dir}/dir_fuzz.json"

    os.makedirs(output_dir, exist_ok=True)

    cmd = [
        'ffuf', '-u', f'{url}/FUZZ',
        '-ac',
        '-w', wordlist_path,
        '-H',
        'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36',
        '-o', out_file
    ]

    print(f"[*] Starting Directory Fuzzer on {url}")
    print(f"[*] Wordlist: {wordlist_path}")

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0 and not os.path.exists(out_file):
        print(f"[-] ffuf failed: {result.stderr.strip()}")
        return

    if not os.path.exists(out_file):
        print("[-] ffuf output file not found")
        return

    url = url.strip()
    parsed_url = urlparse(url)
    clean_url = f"{parsed_url.scheme}://{parsed_url.netloc}"

    web_app = WebApplication.objects.filter(url=clean_url).first()
    if not web_app:
        print(f"[-] WebApplication not found for {url}")
        return

    try:
        with open(out_file, 'r') as f:
            data = json.load(f)
    except json.JSONDecodeError:
        print(f"[-] Failed to parse ffuf output JSON")
        return

    results = data.get('results', [])
    if not results:
        print("[-] No endpoints discovered")
        return

    print(f"[+] Discovered {len(results)} endpoint(s):")
    for entry in results:
        fuzz_word = entry.get('input', {}).get('FUZZ', '')
        path = f"/{fuzz_word}"
        status_code = entry.get('status')
        content_type = entry.get('content-type', '')
        content_length = entry.get('length')
        location_header = entry.get('redirectlocation', '')
        full_url = entry.get('url', '')

        if status_code in [301, 302, 303, 307, 308] and location_header:
            print(f"[+] {full_url} [{status_code}] -> {location_header}")
        else:
            print(f"[+] {full_url} [{status_code}, {content_length}B]")

        EndPoint.objects.update_or_create(
            web_app=web_app,
            path=path,
            defaults={
                'status_code': status_code,
                'content_type': content_type,
                'content_length': content_length,
                'location_header': location_header,
            }
        )

    web_app.analyzed = True
    web_app.save(update_fields=['analyzed'])

    print(f"[+] Directory Fuzzer completed for {url}")
