from backend.core.enum.crawler import crawl
from backend.core.enum.parameter_discovery import extract_parameters
from backend.core.scan.XSS.xss import xss_scan
from backend.core.enum.archived_URLs import get_archived_urls
from urllib.parse import urlparse

def comprehensive_scan(url, auth_headers=None, logout=None):
    crawl(url, auth_headers, logout)
    extract_parameters(url,auth_headers)
    get_archived_urls(urlparse(url).hostname)
    xss_scan(url,auth_headers)
