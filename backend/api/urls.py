from django.contrib import admin
from django.urls import path
from ninja import NinjaAPI, Schema
from typing import List, Optional
from ninja.pagination import paginate, PageNumberPagination
from ninja.errors import HttpError
from backend.api.tasks import enum
from backend.core.models import Company, Domain, Subdomain
from ninja.responses import Response
from celery.result import AsyncResult

api = NinjaAPI(version="1.0.0", title="Recon API")


class HTTPXSchema(Schema):
    url: Optional[str]
    status_code: Optional[int]
    content_length: Optional[int]
    title: Optional[str]
    tech: Optional[list]
    location: Optional[str]


class SubdomainSchema(Schema):
    hostname: str
    is_alive: bool
    cname: Optional[str]
    ip: Optional[str]

    web_fingerprint: List[HTTPXSchema]


class TargetCreateRequest(Schema):
    domain_name: str
    company_name: str


class ScanRequest(Schema):
    domain: str



@api.post("/targets")
def create_target(request, payload: TargetCreateRequest):
    domain_name = payload.domain_name.lower()
    company_name = payload.company_name.lower()

    if Domain.objects.filter(hostname=domain_name).exists():
        return Response({"error": "Domain already exists"}, status=400)

    company, created = Company.objects.get_or_create(name=company_name)
    Domain.objects.create(hostname=domain_name, company=company)

    return Response({
        "status": "success",
        "message": f"Target {domain_name} added to {company_name}"
    }, status=201)


@api.post("/recon")
def create_scan(request, payload: ScanRequest):
    domain = payload.domain.lower()

    if not Domain.objects.filter(hostname=domain).exists():
        return Response({"error": "Domain not found. Please add target first."}, status=404)

    task = enum.delay(domain)

    return Response({
        "success": True,
        "message": f"Recon initiated for {domain}",
        "task_id": task.id
    }, status=202)


@api.get("/recon/{task_id}")
def get_scan_status(request, task_id: str):
    task_result = AsyncResult(task_id)

    result_data = task_result.result if task_result.ready() else None
    if task_result.failed():
        result_data = str(task_result.result)

    return {
        "task_id": task_id,
        "status": task_result.status,
        "result": result_data
    }


@api.get("/subdomains", response=List[SubdomainSchema])
@paginate(PageNumberPagination, page_size=50)
def list_subdomains(request, domain: str, has_website: Optional[bool] = None):
    domain = domain.lower()

    if not Domain.objects.filter(hostname=domain).exists():
        raise HttpError(404, f"Domain '{domain}' not found.")

    qs = Subdomain.objects.filter(domain__hostname=domain)

    if has_website is True:
        qs = qs.filter(web_fingerprint__isnull=False).distinct()
    elif has_website is False:
        qs = qs.filter(web_fingerprint__isnull=True)

    return qs.prefetch_related('web_fingerprint')


urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/", api.urls),
]