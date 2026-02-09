import os, django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backend.api.settings")
django.setup()
from backend.core.models import *

from backend.core.scan.information_disclosure.git_exposures import git_exposures
from backend.core.scan.utils import load_subs, load_urls



domain = "panasonic.com"

load_subs(domain)
load_urls(domain)

git_exposures(domain)