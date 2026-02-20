from ninja import NinjaAPI
from django.shortcuts import get_object_or_404
from django.db.models import Q
from celery.result import AsyncResult
from ninja.pagination import paginate, PageNumberPagination
from .schemas import *
from .tasks import general_scan_task, comprehensive_scan_task

api = NinjaAPI(title="Web-Sploit API")

###################################################################################################
@api.get("/targets/", response=List[TargetOut])
def get_all_targets(request):
    """Get all Targets Information."""
    return Target.objects.prefetch_related('domains').all()

@api.get("/targets/{target_name}/", response=TargetOut)
def get_target(request, target_name: str):
    """Get a Target Information."""
    target_name = target_name.lower()
    return get_object_or_404(Target, name=target_name)

@api.post("/targets/", response=dict)
def create_target(request, payload: TargetIn):
    """Create a Target."""
    target = Target.objects.create(
        name=payload.name.lower(),
        type=payload.type,
        platform=payload.platform,
        program_url=payload.program_url
    )
    for domain_name in payload.domains:
        Domain.objects.create(target=target, hostname=domain_name.lower())
    return {"success": True, "target_name": target.name}


@api.put("/targets/{target_name}/", response=dict)
def update_target(request, target_name: str, payload: TargetUpdate):
    """Update a Target"""
    target_name = target_name.lower()
    target = get_object_or_404(Target, name=target_name)

    for attr, value in payload.dict(exclude_unset=True).items():
        if attr not in ['add_domains', 'remove_domains']:
            if attr == 'name' and isinstance(value, str):
                value = value.lower()
            setattr(target, attr, value)
    target.save()

    if payload.add_domains:
        for domain_name in payload.add_domains:
            Domain.objects.get_or_create(target=target, hostname=domain_name.lower())

    if payload.remove_domains:
        lower_remove_domains = [d.lower() for d in payload.remove_domains]
        Domain.objects.filter(target=target, hostname__in=lower_remove_domains).delete()

    return {"success": True, "message": f"Target '{target.name}' updated successfully"}


@api.delete("/targets/{target_name}/", response=dict)
def delete_target(request, target_name: str):
    """Delete a target"""
    target_name = target_name.lower()
    target = get_object_or_404(Target, name=target_name)
    target.delete()
    return {"success": True, "message": f"Target '{target_name}' deleted successfully"}

##################################################################################################################

@api.post("/scans/general/", response=TaskStatusOut)
def run_general_scan(request, payload: ScanDomainIn):
    task = general_scan_task.delay(
        domain=payload.domain.lower(),
        chunk_size=payload.chunk_size
    )
    return {"task_id": task.id, "status": task.status}


@api.post("/scans/comprehensive/", response=TaskStatusOut)
def run_comprehensive_scan(request, payload: ScanUrlIn):
    task = comprehensive_scan_task.delay(
        url=payload.url,
        auth_headers=payload.auth_headers,
        logout=payload.logout
    )
    return {"task_id": task.id, "status": task.status}


@api.get("/scans/status/{task_id}/", response=dict)
def get_scan_status(request, task_id: str):
    task_result = AsyncResult(task_id)
    return {
        "task_id": task_id,
        "status": task_result.status
    }

##############################################################################################################################

@api.get("/subdomains/{domain_name}/", response=List[SubdomainOut])
@paginate(PageNumberPagination, page_size=500)
def get_domain_subdomains(request, domain_name: str):
    """Get Subdomains"""
    domain_name = domain_name.lower()
    return Subdomain.objects.filter(domain__hostname=domain_name)


@api.get("/webapps/{domain_name}/", response=List[WebAppOut])
@paginate(PageNumberPagination, page_size=500)
def get_domain_webapps(request, domain_name: str):
    """Get Web Apps."""
    domain_name = domain_name.lower()
    return WebApplication.objects.filter(subdomain__domain__hostname=domain_name)

@api.get("/vulnerabilities/{target_name}/", response=List[VulnerabilityOut])
def get_target_vulnerabilities(request, target_name: str):
    """Get vulnerabilities of a Target."""
    target_name = target_name.lower()
    return Vulnerability.objects.filter(
        Q(subdomain__domain__target__name=target_name) |
        Q(web_app__subdomain__domain__target__name=target_name)
    ).select_related('subdomain', 'web_app')


########################################################################################################33
