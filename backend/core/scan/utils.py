import os, django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backend.api.settings")
django.setup()
from backend.core.models import *


def load_html_urls(subdomain, out_file):
    """
    Gets all the urls has content-type text/html and saves them to out_file.
    """

    sub_obj = Subdomain.objects.get(hostname=subdomain)
    urls = URL.objects.filter(
        subdomain=sub_obj,
        content_type__icontains='html'
    )

    req_urls = set()

    for u in urls:
        req_urls.add(u.endpoint)

    with open(out_file, 'w') as file:
        for u in req_urls:
            file.write(f"{u}\n")

def load_parameters(subdomain, out_file):
    """
    Loads all parameters key=value related to the subdomain in out_file.
    """
    sub_obj = Subdomain.objects.get(hostname=subdomain)

    parameters = sub_obj.param.all()

    with open(out_file, 'w') as file:
        for p in parameters:
            file.write(f"{p.key}={p.value}\n")

def load_html_urls_to_set(subdomain):
    """
    Gets all the urls has content-type text/html and returns them in set.
    """

    sub_obj = Subdomain.objects.get(hostname=subdomain)
    urls = URL.objects.filter(
        subdomain=sub_obj,
        content_type__icontains='html'
    )

    req_urls = set()

    for u in urls:
        req_urls.add(u.endpoint)

    return req_urls

def load_parameters_to_set(subdomain):
    """
    Loads all parameters key=value related to the subdomain and returns them in a set.
    """
    sub_obj = Subdomain.objects.get(hostname=subdomain)

    parameters = sub_obj.param.all()

    result = set()

    for p in parameters:
        result.add(f"{p.key}={p.value}")

    return result

def load_subs(domain):
    out_dir = f'/work/backend/core/scan/output/{domain}'
    os.makedirs(out_dir, exist_ok=True)

    subs_file = f'{out_dir}/subs.txt'

    domain_obj = Domain.objects.get(hostname=domain)
    subdomains = domain_obj.subdomains.all()

    with open(subs_file, 'w') as file:
        for i in subdomains:
            file.write(f'{i.hostname}\n')

def load_urls(domain):
    out_dir = f'/work/backend/core/scan/output/{domain}'
    os.makedirs(out_dir, exist_ok=True)

    urls_file = f'{out_dir}/urls.txt'

    urls = WebFingerPrint.objects.filter(subdomain__domain__hostname=domain)

    with open(urls_file, 'w') as file:
        for i in urls:
            file.write(f'{i.url}\n')



