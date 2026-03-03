from backend.core.enum.crawler import crawl
from backend.core.scan.XSS.xss import xss_scan

target = "http://www.dvwa.com"

headers = ["Cookie: PHPSESSID=o2hj1ga3qmpodndqeq3cuq0a11"]

logout = "logout.php"

xss_scan(target, headers)