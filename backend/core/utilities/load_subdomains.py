#Intialize Django.
import os, django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backend.api.settings")
django.setup()
from backend.core.models import *

def load_subdomains(domain, out_file):
    """
    Loads subdomains for a domain from the database and saves them to out_file.
    """
    subdomains = Subdomain.objects.filter(domain__hostname=domain)

    with open(out_file, 'w') as file:
        for i in subdomains:
            file.write(f"{i.hostname}\n")
    pass