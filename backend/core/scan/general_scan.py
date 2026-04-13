from backend.core.scan.information_disclosure.information_disclosure_nuclei import information_disclosure_scan
from backend.core.scan.CVEs.cve import cve_scan
from backend.core.recon.main import recon

def general_scan(domain, chunk_size=None):
    recon(domain, chunk_size=chunk_size)
    information_disclosure_scan(domain)
    cve_scan(domain)
