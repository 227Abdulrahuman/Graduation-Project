from urllib.parse import urlparse
import requests
from backend.core.models import *

def can_connect(url, timeout_seconds=5):
    try:
        requests.head(url, timeout=timeout_seconds, allow_redirects=True)
        return True

    except requests.exceptions.RequestException:
        return False

def analyze_webapp(url, auth_headers=None, logout=None):

    url = url.strip()
    parsed_url = urlparse(url)
    clean_url = f"{parsed_url.scheme}://{parsed_url.netloc}"

    # Strip port number if it exists in netloc
    full_hostname = parsed_url.hostname or parsed_url.netloc.split(':')[0]

    # Check Connection
    if not can_connect(clean_url):
        return

    try:
        web_app = WebApplication.objects.get(url=clean_url)
    except WebApplication.DoesNotExist:
        print(f"[-] Web Application {clean_url} does not exist in the database. Aborting.")
        return

    web_app.analyzed = True
    web_app.save()



    #Crawl Target URL
    from backend.core.enum.crawler import crawl
    crawl(clean_url, url ,auth_headers=auth_headers, logout=logout)


    #Extract Parameters
    from backend.core.enum.parameter_discovery import extract_parameters
    extract_parameters(clean_url,auth_headers=auth_headers, logout=logout)


    #Get Archived URLs
    from backend.core.enum.archived_URLs import get_archived_urls
    get_archived_urls(full_hostname)

    #Download JS Files
    from backend.core.js_analysis.js_downloader import download_js_files
    download_js_files(clean_url)

    #Extract Client Side Routes
    from backend.core.js_analysis.route_extractor import extract_client_side_routes
    extract_client_side_routes(clean_url)


