from backend.core.enum.crawler import crawl


target = "http://www.dvwa.com"

headers = ["Cookie: PHPSESSID=q49sa50lv2333hvl0j7rvckg24"]

logout = "logout.php"

crawl(target, headers, logout)