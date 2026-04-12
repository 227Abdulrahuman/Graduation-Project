import django, subprocess, os, json
from urllib.parse import urlparse

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backend.websploit.settings")
django.setup()
from backend.core.models import WebApplication, EndPoint, Vulnerability


def info_disclosure_scan(url, wordlist_path='/work/backend/core/scan/resources/disclosures.txt'):
    """
    Scans for information disclosures and saves the results to the database.
    """
    domain = urlparse(url).hostname
    output_dir = f'/work/backend/core/output/{domain}'

    out_file = f"{output_dir}/info_disclosure.json"

    os.makedirs(output_dir, exist_ok=True)

    cmd = [
        'ffuf', '-u', f'{url}/FUZZ',
        '-w', wordlist_path,
        '-ac', '-r',
        '-H',
        'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36',
        '-o', out_file
    ]

    print(f"\n[*] Starting Disclosures scan on {url}")
    subprocess.run(cmd, capture_output=True, text=True)

    if not os.path.exists(out_file):
        print(f"[-] FFUF output file not found: {out_file}")
        return

    web_app = WebApplication.objects.filter(url=url).first()

    try:
        with open(out_file, 'r') as f:
            data = json.load(f)
            results = data.get('results', [])

            if not results:
                print("[-] No information disclosures found.")
                return

            print("\n[+] Discovered Potential Disclosures:")
            for result in results:
                fuzz_word = result.get('input', {}).get('FUZZ', '')
                path = f"/{fuzz_word}"
                status_code = result.get('status')
                content_type = result.get('content-type', '')
                content_length = result.get('length')
                location_header = result.get('redirectlocation', '')
                full_url = result.get('url', '')

                if status_code in [301, 302, 303, 307, 308] and location_header:
                    print(
                        f"  -> {full_url} [Status: {status_code}, Length: {content_length}] -> Redirects to: {location_header}")
                else:
                    print(f"  -> {full_url} [Status: {status_code}, Length: {content_length}]")


                endpoint_obj, created = EndPoint.objects.update_or_create(
                    web_app=web_app,
                    path=path,
                    defaults={
                        'status_code': status_code,
                        'content_type': content_type,
                        'content_length': content_length,
                        'location_header': location_header
                    }
                )

                Vulnerability.objects.update_or_create(
                    endpoint=endpoint_obj,
                    name="Information Disclosure",
                    defaults={
                        'location': full_url,
                        'severity': 'Medium',
                        'type': 'Misconfigurations'
                    }
                )

        print(f"\n[+] Finished Disclosures scan on {url}")

    except json.JSONDecodeError:
        print(f"[-] Failed to parse JSON file at {out_file}. The file might be corrupted.")
    except Exception as e:
        print(f"[-] An error occurred while processing results: {e}")