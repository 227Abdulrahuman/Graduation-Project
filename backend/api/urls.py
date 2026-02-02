from django.contrib import admin
from django.urls import path
from ninja import NinjaAPI, Schema
from typing import List, Optional
from ninja.pagination import paginate, PageNumberPagination
from ninja.errors import HttpError
from django.shortcuts import get_object_or_404
from ninja.responses import Response
from celery.result import AsyncResult

from backend.core.models import Company, Domain, Subdomain, WebFingerPrint
from backend.api.tasks import enum  # Assuming this is your Celery task

api = NinjaAPI(version="1.0.0", title="Recon API")


class CompanyCreateSchema(Schema):
    name: str
    platform: Optional[str] = None
    program_url: Optional[str] = None
    domains: List[str]

class ScanRequest(Schema):
    domain: str


class WebFingerprintSchema(Schema):
    url: Optional[str]
    status_code: Optional[int]
    title: Optional[str]
    tech: Optional[list]
    content_length: Optional[int]
    location: Optional[str]


class WebsiteResponseSchema(Schema):
    hostname: str
    ip: Optional[str]
    web_fingerprint: List[WebFingerprintSchema]


class DNSResponseSchema(Schema):
    hostname: str
    is_alive: bool
    cname: Optional[str]
    ip: Optional[str]


@api.post("/companies", response={201: dict, 400: dict})
def create_company(request, payload: CompanyCreateSchema):
    """
    Add a company with attributes and multiple domains.
    """
    company, created = Company.objects.update_or_create(
        name=payload.name.lower(),
        defaults={
            'platform': payload.platform,
            'program_url': payload.program_url
        }
    )

    created_domains = []
    existing_domains = []

    for domain_name in payload.domains:
        d_name = domain_name.lower()
        if Domain.objects.filter(hostname=d_name).exists():
            existing_domains.append(d_name)
        else:
            Domain.objects.create(hostname=d_name, company=company)
            created_domains.append(d_name)

    return Response({
        "status": "success",
        "company": company.name,
        "domains_added": created_domains,
        "domains_skipped_existing": existing_domains
    }, status=201)


@api.post("/recon/start", response={202: dict, 404: dict})
def perform_recon(request, payload: ScanRequest):
    """
    Trigger the Celery recon task for a specific domain.
    """
    domain = payload.domain.lower()

    if not Domain.objects.filter(hostname=domain).exists():
        return Response({"error": f"Domain {domain} not found in database. Add company first."}, status=404)

    task = enum.delay(domain)

    return Response({
        "success": True,
        "message": f"Recon initiated for {domain}",
        "task_id": task.id
    }, status=202)


@api.get("/recon/status/{task_id}")
def get_recon_status(request, task_id: str):
    """
    Check the status of a running Celery task.
    """
    task_result = AsyncResult(task_id)

    result_data = task_result.result if task_result.ready() else None

    if task_result.failed():
        result_data = str(task_result.result)

    return {
        "task_id": task_id,
        "status": task_result.status,
        "result": result_data
    }


@api.get("/results/websites", response=List[WebsiteResponseSchema])
@paginate(PageNumberPagination, page_size=50)
def get_websites(request, domain: Optional[str] = None):
    """
    Return ONLY subdomains that have a WebFingerprint (Status code, title, etc).
    """
    qs = Subdomain.objects.filter(web_fingerprint__isnull=False).distinct()

    if domain:
        qs = qs.filter(domain__hostname=domain.lower())

    return qs.prefetch_related('web_fingerprint')


@api.get("/results/dns", response=List[DNSResponseSchema])
@paginate(PageNumberPagination, page_size=50)
def get_dns_records(request, domain: Optional[str] = None):
    """
    Return subdomains WITHOUT websites (Pure DNS data: CNAME, IP, etc).
    """
    qs = Subdomain.objects.filter(web_fingerprint__isnull=True)

    if domain:
        qs = qs.filter(domain__hostname=domain.lower())

    return qs


urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/", api.urls),
]