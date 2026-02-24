from backend.core.enum.crawler import crawl
from backend.core.enum.parameter_discovery import extract_parameters
from backend.core.scan.XSS.xss import xss_scan
from backend.core.enum.archived_URLs import get_archived_urls
from backend.core.utilities.urls_shortener import shorten_urls
from urllib.parse import urlparse
import os, subprocess
from backend.core.utilities.loaders import load_html_urls_to_set, load_parameters_to_set

def comprehensive_scan_init(url):
    """
    Prepare the URLs and Parameters Combinations for scanning.
    """

    domain = urlparse(url).hostname
    output_dir = f'/work/backend/core/output/{domain}'
    os.makedirs(output_dir, exist_ok=True)

    targets_file = f"{output_dir}/scan_targets.txt"
    urls_file = f"{output_dir}/urls.txt"
    shortened_urls_file = f"{output_dir}/urls_short.txt"

    urls = load_html_urls_to_set(url)
    params = load_parameters_to_set(url)
    short_urls = shorten_urls(urls)

    #Write all URLs to a file.
    with open(urls_file, 'w') as file:
        for u in urls:
            file.write(f"{u}\n")

    #Write shortened URLs.
    with open(shortened_urls_file, 'w') as file:
        for u in short_urls:
            file.write(f"{u}\n")


    #Generate URLs and Parameters Combinations.
    with open(targets_file, 'w') as file:
        for u in short_urls:
            for p in params:
                file.write(f"{u}?{p}\n")


def comprehensive_scan(url, auth_headers=None, logout=None):
    crawl(url, auth_headers=auth_headers, logout=logout)
    extract_parameters(url,auth_headers=auth_headers)
    # get_archived_urls(urlparse(url).hostname)
    comprehensive_scan_init(url)
    xss_scan(url,auth_headers=auth_headers)
