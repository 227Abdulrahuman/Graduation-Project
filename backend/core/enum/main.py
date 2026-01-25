import os, django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backend.api.settings")
django.setup()
from backend.core.models import *

from backend.core.enum.crawler import crawl
from backend.core.enum.parameter_discovery import parameter_extractor


#
# target_url = "https://seikitoriatsukaiten.jp.eww.panasonic.com/"
#
# crawl(target_url)
# parameter_extractor(target_url)


from backend.core.scan.cross_site_scripting.xss import xss_scan

xss_scan("seikitoriatsukaiten.jp.eww.panasonic.com")
