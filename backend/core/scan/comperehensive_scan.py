from backend.core.enum.crawler import crawl
from backend.core.enum.parameter_discovery import extract_parameters
from backend.core.scan.XSS.xss import xss_scan
from backend.core.scan.path_traversal.path_traversal import path_traversal_scan
from backend.core.enum.archived_URLs import get_archived_urls
from backend.core.utilities.declutter import declutter_urls
from urllib.parse import urlparse
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


    urls = load_html_urls_to_set(url)
    urls = declutter_urls(urls)

    xss_params = load_xss_parameters_to_set(url)
    path_traversal_params = load_path_traversal_parameters_to_set(url)


    #Generate URLs and Parameters Combinations.
    with open(xss_targets_file, 'w') as file:
        for u in urls:
            if logout is not None:
                if logout not in u:
                    for p in xss_params:
                        file.write(f"{u}?{p}\n")
            else:
                for p in xss_params:
                    file.write(f"{u}?{p}\n")

    with open(path_traversal_targets_file, 'w') as file:
        for u in urls:
            if logout is not None:
                if logout not in u:
                    for p in path_traversal_params:
                        file.write(f"{u}?{p}\n")
            else:
                for p in path_traversal_params:
                    file.write(f"{u}?{p}\n")


def comprehensive_scan(url, auth_headers=None, logout=None):
    crawl(url, auth_headers=auth_headers, logout=logout)
    extract_parameters(url,auth_headers=auth_headers,logout=logout)
    comprehensive_scan_init(url,logout=logout)
    xss_scan(url,auth_headers=auth_headers)
    path_traversal_scan(url, auth_headers=auth_headers)
