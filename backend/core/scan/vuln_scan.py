from backend.core.scan.XSS.xss import xss_scan
from backend.core.scan.SQLi.sqli import sqli_scan
from backend.core.scan.open_redirect.open_redirect import open_redirect_scan
from backend.core.scan.path_traversal.path_traversal import path_traversal_scan


def vuln_scan(url, auth_headers=None, run_xss=True, run_sqli=True, run_open_redirect=True, run_path_traversal=True):
    """
    Runs selected vulnerability scans against the given URL.
    """
    if run_xss:
        xss_scan(url, auth_headers=auth_headers)

    if run_sqli:
        sqli_scan(url, auth_headers=auth_headers)

    if run_open_redirect:
        open_redirect_scan(url, auth_headers=auth_headers)

    if run_path_traversal:
        path_traversal_scan(url, auth_headers=auth_headers)
