from backend.core.enum.crawler import crawl
from backend.core.enum.parameter_discovery import extract_parameters
from backend.core.scan.XSS.xss import xss_scan
from backend.core.scan.path_traversal.path_traversal import path_traversal_scan
from backend.core.enum.archived_URLs import get_archived_urls
from backend.core.utilities.urls_shortener import shorten_urls
from urllib.parse import urlparse
import os, subprocess
from backend.core.utilities.loaders import *

def comprehensive_scan_init(url, logout=None):
    """
    Prepare the URLs and Parameters Combinations for scanning.
    """

    domain = urlparse(url).hostname
    output_dir = f'/work/backend/core/output/{domain}'
    os.makedirs(output_dir, exist_ok=True)

    xss_targets_file = f"{output_dir}/xss_scan_targets.txt"
    path_traversal_targets_file = f"{output_dir}/path_traversal_scan_targets.txt"

    urls_file = f"{output_dir}/urls.txt"
    shortened_urls_file = f"{output_dir}/urls_short.txt"

    urls = load_html_urls_to_set(url)
    xss_params = load_xss_parameters_to_set(url)
    path_traversal_params = load_path_traversal_parameters_to_set(url)

    short_urls = shorten_urls(urls)

    # #Write all URLs to a file.
    # with open(urls_file, 'w') as file:
    #     for u in urls:
    #         file.write(f"{u}\n")

    # #Write shortened URLs.
    # with open(shortened_urls_file, 'w') as file:
    #     for u in short_urls:
    #         file.write(f"{u}\n")


    #Generate URLs and Parameters Combinations.
    with open(xss_targets_file, 'w') as file:
        for u in urls:
            if logout not in u:
                for p in xss_params:
                    file.write(f"{u}?{p}\n")

    with open(path_traversal_targets_file, 'w') as file:
        for u in urls:
            if logout not in u:
                for p in path_traversal_params:
                    file.write(f"{u}?{p}\n")


def comprehensive_scan(url, auth_headers=None, logout=None):
    crawl(url, auth_headers=auth_headers, logout=logout)
    extract_parameters(url,auth_headers=auth_headers,logout=logout)
    comprehensive_scan_init(url,logout=logout)
    xss_scan(url,auth_headers=auth_headers)
    path_traversal_scan(url, auth_headers=auth_headers)
