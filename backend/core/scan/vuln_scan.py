from backend.core.scan.XSS.xss import xss_scan
from backend.core.scan.SQLi.sqli import sqli_scan
from backend.core.scan.open_redirect.open_redirect import open_redirect_scan
from backend.core.scan.path_traversal.path_traversal import path_traversal_scan
from urllib.parse import urlparse


def vuln_scan(url, auth_headers=None, run_xss=True, run_sqli=True, run_open_redirect=True, run_path_traversal=True):
    """
    Runs selected vulnerability scans against the given URL.
    """

    url = url.strip()
    parsed_url = urlparse(url)
    clean_url = f"{parsed_url.scheme}://{parsed_url.netloc}"

    if run_xss:
        xss_scan(clean_url, auth_headers=auth_headers)

    if run_sqli:
        sqli_scan(clean_url, auth_headers=auth_headers)

    if run_open_redirect:
        open_redirect_scan(clean_url, auth_headers=auth_headers)

    if run_path_traversal:
        path_traversal_scan(clean_url, auth_headers=auth_headers)
