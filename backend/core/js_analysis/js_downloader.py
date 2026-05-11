import requests
from urllib.parse import urljoin, urlparse
import urllib3
import jsbeautifier
#Connect to Django
import os, django, subprocess
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backend.websploit.settings")
django.setup()
from backend.core.models import WebApplication, EndPoint, JSFile

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def download_js_files(webapp_url):
    """
    Downloads all the js files for a certain webapp.
    Saves them in /backend/output/{subdomain}/{webappurl}/js/
    Also saves beautified content to the database.
    """
    
    try:
        webapp = WebApplication.objects.get(url=webapp_url)
    except WebApplication.DoesNotExist:
        print(f"[-] WebApplication with URL {webapp_url} does not exist in the database.")
        return None

    subdomain = webapp.subdomain.hostname

    # Sanitize webapp_url for filesystem usage
    clean_webapp_url = webapp_url.replace("://", "_").replace("/", "_").replace(".", "_").replace(":", "_")
    

    output_dir = os.path.join('/work', 'output', subdomain, clean_webapp_url, 'js')
    
    os.makedirs(output_dir, exist_ok=True)
    
    print(f"[*] Identifying JS files for {webapp_url}")
    
    js_urls = set()

    try:
        # Check by extension
        endpoints_ext = EndPoint.objects.filter(web_app__url=webapp_url, path__endswith='.js')
        for ep in endpoints_ext:
            full_url = urljoin(webapp_url, ep.path)
            js_urls.add(full_url)
            
        # Check by content_type (case-insensitive "javascript")
        endpoints_ct = EndPoint.objects.filter(web_app__url=webapp_url, content_type__icontains='javascript')
        for ep in endpoints_ct:
            full_url = urljoin(webapp_url, ep.path)
            js_urls.add(full_url)
    except Exception as e:
        print(f"[-] Database query failed: {e}")
        

    if not js_urls:
        print(f"[-] No JS files discovered for {webapp_url}")
        return None

    print(f"[*] Found {len(js_urls)} unique JS URLs. Starting download...")
    
    downloaded_count = 0
    opts = jsbeautifier.default_options()
    opts.indent_size = 2

    for js_url in js_urls:
        try:
            parsed_js = urlparse(js_url)
            filename = os.path.basename(parsed_js.path)
            

            if not filename or '.js' not in filename.lower():

                if '.js' in parsed_js.path.lower():
                    filename = parsed_js.path.split('/')[-1]
                else:
                    filename = f"script_{hash(js_url)}.js"
            

            if '?' in filename:
                filename = filename.split('?')[0]
            
            if not filename.endswith('.js'):
                filename += '.js'

            filepath = os.path.join(output_dir, filename)
            
            # Download the JS file
            js_resp = requests.get(js_url, timeout=15, verify=False)
            if js_resp.status_code == 200:
                # Beautify the content
                beautified_js = jsbeautifier.beautify(js_resp.text, opts)
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(beautified_js)
                
                # Save to database
                JSFile.objects.update_or_create(
                    web_app=webapp,
                    name=filename,
                    defaults={
                        'content': beautified_js,
                        'url': js_url
                    }
                )
                
                downloaded_count += 1
        except Exception as e:
            pass
            
    print(f"[+] Successfully downloaded {downloaded_count} JS files.")
    return output_dir

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        download_js_files(sys.argv[1])
    else:
        print("Usage: python3 js_downloader.py <webapp_url>")
