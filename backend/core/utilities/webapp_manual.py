import subprocess
import json
from urllib.parse import urlparse
from backend.core.models import Subdomain, WebApplication

def add_webapp_manually(url):
    """
    Runs httpx on a single URL and saves the result to the database.
    Only proceeds if the subdomain already exists.
    """
    url = url.strip()
    parsed_url = urlparse(url)
    
    # Normalize URL to strip paths, queries, etc.
    clean_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    
    # We want to match the subdomain hostname
    full_hostname = parsed_url.hostname or parsed_url.netloc.split(':')[0]
    
    try:
        subdomain_obj = Subdomain.objects.get(hostname=full_hostname)
    except Subdomain.DoesNotExist:
        print(f"[-] Subdomain {full_hostname} does not exist in the database. Aborting.")
        return False

    print(f"[*] Running HTTPX on {clean_url}...")
    
    # Run httpx
    cmd = [
        'httpx', '-u', clean_url,
        '-silent', '-nc',
        '-sc', '-title', '-location', '-td', '-cl',
        '-j'
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"[-] HTTPX failed: {result.stderr}")
            return False
            
        output = result.stdout.strip()
        if not output:
            print(f"[-] HTTPX returned no output for {url}")
            return False
            
        data = json.loads(output)
        
        target_url = data.get('url')
        status_code = data.get('status_code')
        content_length = data.get('content_length')
        tech = data.get('tech', [])
        title = data.get('title')
        location = data.get('location')
        
        web_app, created = WebApplication.objects.update_or_create(
            url=target_url,
            defaults={
                "subdomain": subdomain_obj,
                "status_code": status_code,
                "content_length": content_length,
                "tech_stack": tech,
                "title": title,
                "location": location,
                "analyzed": True
            }
        )
        
        action = "Created" if created else "Updated"
        print(f"[+] Successfully {action} Web Application: {target_url}")
        return True
        
    except Exception as e:
        print(f"[-] Error adding webapp: {e}")
        return False
