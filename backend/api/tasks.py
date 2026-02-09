from celery import shared_task
from backend.core.recon.main import recon_pipline
from backend.core.scan.general_scan import general_scan

@shared_task
def enum(domain):
    recon_pipline(domain)

@shared_task
def scan(domain):
    general_scan(domain)