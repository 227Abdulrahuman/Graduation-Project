import os
import json
import subprocess
import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backend.websploit.settings")
django.setup()

from backend.core.models import WebApplication, ClientSideRoute


def extract_client_side_routes(webapp_url):
    """
    Extracts client-side routes from downloaded JS files using jsluice.
    """
    try:
        webapp = WebApplication.objects.get(url=webapp_url)
    except WebApplication.DoesNotExist:
        print(f"[-] WebApplication with URL {webapp_url} does not exist in the database.")
        return

    subdomain = webapp.subdomain.hostname
    clean_webapp_url = webapp_url.replace("://", "_").replace("/", "_").replace(".", "_").replace(":", "_")
    js_dir = os.path.join('/work', 'output', subdomain, clean_webapp_url, 'js')
    
    if not os.path.exists(js_dir):
        print(f"[-] JS directory {js_dir} does not exist.")
        return

    # get path to jsluice
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    jsluice_bin = os.path.join(base_dir, 'bins', 'jsluice')

    if not os.path.exists(jsluice_bin):
        print(f"[-] jsluice binary not found at {jsluice_bin}")
        return

    print(f"[*] Extracting client side routes for {webapp_url}")

    extracted_routes = set()
    
    for filename in os.listdir(js_dir):
        if filename.endswith(".js"):
            filepath = os.path.join(js_dir, filename)
            
            try:
                # Run jsluice urls <file>
                result = subprocess.run([jsluice_bin, 'urls', filepath], capture_output=True, text=True)
                if result.returncode == 0:
                    for line in result.stdout.splitlines():
                        if not line.strip():
                            continue
                        try:
                            data = json.loads(line)
                            url = data.get("url")
                            if url:
                                extracted_routes.add(url)
                        except json.JSONDecodeError:
                            pass
            except Exception as e:
                print(f"[-] Error processing {filename} with jsluice: {e}")
                
    if not extracted_routes:
        print(f"[-] No client side routes found for {webapp_url}")
        return
        
    print(f"[*] Found {len(extracted_routes)} unique client side routes. Saving to database...")
    
    saved_count = 0
    for route_url in extracted_routes:
        try:
            ClientSideRoute.objects.update_or_create(
                web_app=webapp,
                url=route_url
            )
            saved_count += 1
        except Exception as e:
            pass
            
    print(f"[+] Successfully saved {saved_count} client side routes.")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        extract_client_side_routes(sys.argv[1])
    else:
        print("Usage: python3 route_extractor.py <webapp_url>")
