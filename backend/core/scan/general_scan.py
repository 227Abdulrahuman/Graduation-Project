from backend.core.scan.information_disclosure.information_disclosure import information_disclosure_scan
from backend.core.scan.CVEs.cve import cve_scan



def general_scan(domain):
    information_disclosure_scan(domain)
    cve_scan(domain)
