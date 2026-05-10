from backend.core.scan.XSS.xss import xss_scan
from backend.core.scan.path_traversal.path_traversal import path_traversal_scan
from backend.core.scan.SQLi.sqli import sqli_scan
from backend.core.scan.open_redirect.open_redirect import open_redirect_scan
from backend.core.utilities.declutter import declutter_urls
from backend.core.utilities.loaders import *
from backend.core.utilities.url_operations import  count_path_parts
from urllib.parse import urlparse

def comprehensive_scan_init(url, logout=None):
    """
    Prepare the URLs and Parameters Combinations for scanning.
    """

    domain = urlparse(url).hostname
    output_dir = f'/work/output/{domain}'
    os.makedirs(output_dir, exist_ok=True)

    xss_targets_file = f"{output_dir}/xss_scan_targets.txt"
    path_traversal_targets_file = f"{output_dir}/path_traversal_scan_targets.txt"
    sqli_targets_file = f"{output_dir}/sqli_scan_targets.txt"
    open_redirect_targets_file = f"{output_dir}/open_redirect_targets.txt"

    urls = load_html_urls_to_set(url, logout=logout)
    urls = declutter_urls(urls)

    web_app = WebApplication.objects.get(url=url)
    #Generate URLs and Parameters Combinations.
    with open(xss_targets_file, 'w') as file:
        for u in urls:
            endpoint_path = urlparse(u).path
            endpoint = EndPoint.objects.get(web_app=web_app, path=endpoint_path)
            parameters = endpoint.parameter.all()

            for param in parameters:
                file.write(f'{u}?{param.key}="websploit"\n')

    with open(path_traversal_targets_file, 'w') as file:
        for u in urls:
            endpoint_path = urlparse(u).path
            endpoint = EndPoint.objects.get(web_app=web_app, path=endpoint_path)
            parameters = endpoint.parameter.all()

            for param in parameters:
                file.write(f'{u}?{param.key}=/etc/passwd\n')
                file.write(f'{u}?{param.key}=../../../../../../../../../etc/passwd\n')
                file.write(f'{u}?{param.key}=\\Windows\\win.ini\n')
                file.write(f'{u}?{param.key}=..\\..\\..\\..\\..\\..\\..\\..\\..\\Windows\\win.ini\n')

    with open(sqli_targets_file, 'w') as file:
        for u in urls:
            endpoint_path = urlparse(u).path
            endpoint = EndPoint.objects.get(web_app=web_app, path=endpoint_path)
            parameters = endpoint.parameter.all()

            for param in parameters:
                file.write(f"{u}?{param.key}=web_sploit'\n")

    with open(open_redirect_targets_file, 'w') as file:
        for u in urls:
            if count_path_parts(u) == 1:
                parsed = urlparse(u)
                new_u = f'{parsed.scheme}://{parsed.hostname}/{parsed.path.rstrip("/")}@www.google.com'
                file.write(f"{new_u}\n")

            endpoint_path = urlparse(u).path
            endpoint = EndPoint.objects.get(web_app=web_app, path=endpoint_path)
            parameters = endpoint.parameter.all()

            for param in parameters:
                file.write(f"{u}?{param.key}=https://www.google.com/\n")



def comprehensive_scan(url, auth_headers=None, logout=None):
    url = url.strip()
    parsed_url = urlparse(url)
    url = f"{parsed_url.scheme}://{parsed_url.netloc}"

    from backend.core.scan.webapp_analysis import can_connect
    if not can_connect(url):
        return

    comprehensive_scan_init(url,logout=logout)

    xss_scan(url,auth_headers=auth_headers)
    open_redirect_scan(url, auth_headers=auth_headers)
    sqli_scan(url, auth_headers=auth_headers)
    path_traversal_scan(url, auth_headers=auth_headers)
