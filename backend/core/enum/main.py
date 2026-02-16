url = "https://spc.jp.eww.panasonic.com"

from backend.core.enum.crawler import crawl
crawl(url)

from backend.core.enum.parameter_discovery import parameter_extractor
parameter_extractor(url)

from backend.core.scan.XSS.xss import xss_scan


xss_scan(url)