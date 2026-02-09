import os, django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backend.api.settings")
django.setup()
from backend.core.models import *

from backend.core.scan.information_disclosure.git_exposures import git_exposures
from backend.core.scan.CVEs.cve import cve_check
from backend.core.scan.subdomain_takeover.takeover import takeover

def general_scan(domain):
    git_exposures(domain)
    cve_check(domain)
    takeover(domain)