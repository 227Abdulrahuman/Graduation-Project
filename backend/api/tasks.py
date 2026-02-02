from celery import shared_task
from backend.core.recon.main import recon_pipline

@shared_task
def enum(domain):
    recon_pipline(domain)