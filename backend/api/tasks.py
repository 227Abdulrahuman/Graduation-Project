from celery import shared_task
from backend.core.scan.general_scan import general_scan
from backend.core.scan.comperehensive_scan import comprehensive_scan

@shared_task
def general_scan_task(domain, chunk_size=None):
    general_scan(domain, chunk_size=chunk_size)

@shared_task
def comprehensive_scan_task(url, auth_headers=None, logout=None):
    comprehensive_scan(url, auth_headers=auth_headers, logout=logout)