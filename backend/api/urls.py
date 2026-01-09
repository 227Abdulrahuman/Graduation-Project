from django.contrib import admin
from django.urls import path
from ninja import NinjaAPI
from ninja import Schema, ModelSchema
from typing import List, Optional
from ninja.pagination import paginate, PageNumberPagination
from ninja.errors import HttpError
from backend.api.tasks import enum
from backend.core.models import *
from ninja.responses import Response
from celery.result import AsyncResult

api = NinjaAPI()

class HTTPXSchema(Schema):
    url: Optional[str]
    status_code: Optional[int]
    content_length: Optional[int]
    tech: Optional[list]
    location: Optional[str]
    title: Optional[str]

class SubdomainSchema(Schema):
    hostname: str
    is_alive: bool
    cname: Optional[str]
    ip: Optional[str]
    web_fingerprint: List[HTTPXSchema]

@api.get("addCompany")
def add_company(request, company_name:str):
    company_name = company_name.lower()
    if Company.objects.filter(name=company_name).exists():
        return Response({"error":"Company already exists"}, status=400)
    else:
        Company.objects.create(name=company_name)
        return Response({"status":"success"}, status=201)

@api.get("addDomain")
def add_domain(request, domain_name:str, company_name:str):
    domain_name = domain_name.lower()
    company_name = company_name.lower()
    if Domain.objects.filter(hostname=domain_name).exists():
        return Response({"error":"Domain already exists"}, status=400)
    else:
        company, created = Company.objects.get_or_create(name=company_name)
        Domain.objects.create(hostname=domain_name, company=company)
        return Response({"status":"success"}, status=201)

@api.get("startRecon")
def recon(request, domain: str):
    domain = domain.lower()
    if Domain.objects.filter(hostname=domain).exists():
        task = enum.delay(domain)
        return Response({
            "success": f"started recon pipeline on {domain}",
            "task_id": task.id
        }, status=200)
    else:
        return Response({"error": "Domain does not exist"}, status=400)


@api.get("getReconStatus")
def get_recon_status(request, task_id: str):
    task_result = AsyncResult(task_id)
    return {
        "task_id": task_id,
        "status": task_result.status,
        "result": str(task_result.result) if task_result.failed() else task_result.result
    }

@api.get("getReconData", response={200: List[SubdomainSchema], 404: dict})
@paginate(PageNumberPagination, page_size=50)
def get_recon_data(request, domain_name: str):
    domain_name = domain_name.lower()
    if not Domain.objects.filter(hostname=domain_name).exists():
        raise HttpError(404, f"Domain '{domain_name}' not found in database.")

    res = Subdomain.objects.filter(domain__hostname=domain_name).prefetch_related('web_fingerprint')
    return res


# @api.get("scan")
# def vuln_scan(request, domain:str):
#     domain = domain.lower()
#     if Domain.objects.filter(hostname=domain).exists():
#         scan.delay(domain)
#         return Response({f"success":f"started scanning {domain}"}, status=200)
#     else:
#         return Response({"error":"Domain does not exist"}, status=400)

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/", api.urls),
]