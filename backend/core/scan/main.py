import os, django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backend.api.settings")
django.setup()
from backend.core.models import *

from backend.core.scan.cross_site_scripting.xss import xss_scan



xss_scan("seikitoriatsukaiten.jp.eww.panasonic.com")