from urllib.parse import urlparse
import requests
from backend.core.models import *
import tldextract

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

    ext = tldextract.extract(full_hostname)

    if ext.suffix:
        apex_domain = f"{ext.domain}.{ext.suffix}"
    else:
        apex_domain = full_hostname

    target_obj, _ = Target.objects.get_or_create(
        name=apex_domain,
        defaults={'type': 'Auto-Generated'}
    )

    domain_obj, _ = Domain.objects.get_or_create(
        hostname=apex_domain,
        defaults={'target': target_obj}
    )

    sub_obj, _ = Subdomain.objects.get_or_create(
        hostname=full_hostname,
        defaults={'domain': domain_obj}
    )

    web_app, _ = WebApplication.objects.get_or_create(
        url=clean_url,
        defaults={
            'subdomain': sub_obj
        }
    )

    web_app.analyzed = True
    web_app.save()


    #Check Connection
    if not can_connect(clean_url):
        return


    #Crawl Target URL
    from backend.core.enum.crawler import crawl
    crawl(clean_url, auth_headers=auth_headers, logout=logout)


    #Extract Parameters
    from backend.core.enum.parameter_discovery import extract_parameters
    extract_parameters(clean_url,auth_headers=auth_headers, logout=logout)


    #Get Archived URLs
    from backend.core.enum.archived_URLs import get_archived_urls
    get_archived_urls(full_hostname)


