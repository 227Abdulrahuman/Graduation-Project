from ninja import NinjaAPI
from django.db import transaction
import tldextract
from urllib.parse import urlparse
from django.shortcuts import get_object_or_404
from django.db.models import Q
from celery.result import AsyncResult
from ninja.pagination import paginate, PageNumberPagination
from .schemas import *
from .tasks import general_scan_task, comprehensive_scan_task

api = NinjaAPI(title="Web-Sploit API")

def get_target_by_identifier(identifier: str):
    if identifier.isdigit():
        return get_object_or_404(Target, id=int(identifier))
    return get_object_or_404(Target, name=identifier.lower())

@api.get("/targets/", response=List[TargetOut])
@paginate(PageNumberPagination, page_size=500)
def get_all_targets(request):
    return Target.objects.prefetch_related('domains').all()


@api.get("/targets/{target_identifier}/", response=TargetOut)
def get_target(request, target_identifier: str):
    return get_target_by_identifier(target_identifier)


@api.post("/targets/", response=dict)
def create_target(request, payload: TargetIn):
    target = Target.objects.create(
        name=payload.name.lower(),
        type=payload.type,
        platform=payload.platform,
        program_url=payload.program_url
    )
    for domain_name in payload.domains:
        Domain.objects.create(target=target, hostname=domain_name.lower())

    return {"success": True, "target_id": target.id, "target_name": target.name}


@api.put("/targets/{target_identifier}/", response=dict)
def update_target(request, target_identifier: str, payload: TargetUpdate):
    target = get_target_by_identifier(target_identifier)

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

    return {
        "success": True,
        "message": f"Target updated successfully",
        "target_id": target.id,
        "target_name": target.name
    }


@api.delete("/targets/{target_identifier}/", response=dict)
def delete_target(request, target_identifier: str):
    target = get_target_by_identifier(target_identifier)

    target_id = target.id
    target_name = target.name
    target.delete()

    return {
        "success": True,
        "message": f"Target deleted successfully",
        "target_id": target_id,
        "target_name": target_name
    }


@api.post("/scans/general/", response=TaskStatusOut)
def run_general_scan(request, payload: ScanDomainIn):
    task = general_scan_task.delay(
        domain=payload.domain.lower(),
        chunk_size=payload.chunk_size
    )
    return {"task_id": task.id, "status": task.status}


@api.post("/scans/comprehensive/", response=TaskStatusOut)
def run_comprehensive_scan(request, payload: ScanUrlIn):
    raw_url = payload.url.strip()

    parsed_url = urlparse(raw_url)
    normalized_url = f"{parsed_url.scheme}://{parsed_url.netloc}"

    task = comprehensive_scan_task.delay(
        url=normalized_url,
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


@api.get("/subdomains/", response=List[SubdomainOut])
@paginate(PageNumberPagination, page_size=500)
def get_subdomains(request, target_identifier: Optional[str] = None, domain: Optional[str] = None):
    query = Q()

    if target_identifier:
        if target_identifier.isdigit():
            query |= Q(domain__target__id=int(target_identifier))
        else:
            query |= Q(domain__target__name=target_identifier.lower())

    if domain:
        query |= Q(domain__hostname=domain.lower())

    return Subdomain.objects.filter(query)


@api.get("/webapps/", response=List[WebAppOut])
@paginate(PageNumberPagination, page_size=500)
def get_webapps(
        request,
        target_identifier: Optional[str] = None,
        domain: Optional[str] = None,
        status_code: Optional[int] = None,
        content_length: Optional[int] = None,
        tech_stack: Optional[str] = None
):
    identifier_query = Q()
    if target_identifier:
        if target_identifier.isdigit():
            identifier_query |= Q(subdomain__domain__target__id=int(target_identifier))
        else:
            identifier_query |= Q(subdomain__domain__target__name=target_identifier.lower())

    if domain:
        identifier_query |= Q(subdomain__domain__hostname=domain.lower())

    main_query = Q()

    if target_identifier or domain:
        main_query &= identifier_query

    if status_code is not None:
        main_query &= Q(status_code=status_code)

    if content_length is not None:
        main_query &= Q(content_length=content_length)

    if tech_stack:
        main_query &= Q(tech_stack__icontains=tech_stack)

    return WebApplication.objects.filter(main_query)


@api.get("/vulnerabilities/", response=List[VulnerabilityOut])
@paginate(PageNumberPagination, page_size=500)
def get_vulnerabilities(
        request,
        target_identifier: Optional[str] = None,
        domain: Optional[str] = None,
        url: Optional[str] = None,
        vuln_severity: Optional[str] = None,
        vuln_type: Optional[str] = None,
        vuln_name: Optional[str] = None
):
    identifier_query = Q()

    if target_identifier:
        if target_identifier.isdigit():
            identifier_query |= (
                    Q(subdomain__domain__target__id=int(target_identifier)) |
                    Q(web_app__subdomain__domain__target__id=int(target_identifier))
            )
        else:
            target_name = target_identifier.lower()
            identifier_query |= (
                    Q(subdomain__domain__target__name=target_name) |
                    Q(web_app__subdomain__domain__target__name=target_name)
            )

    if domain:
        domain_lower = domain.lower()
        identifier_query |= (
                Q(subdomain__domain__hostname=domain_lower) |
                Q(web_app__subdomain__domain__hostname=domain_lower)
        )

    if url:
        identifier_query |= Q(web_app__url=url)

    main_query = Q()

    if target_identifier or domain or url:
        main_query &= identifier_query

    if vuln_severity:
        main_query &= Q(severity__iexact=vuln_severity)

    if vuln_type:
        main_query &= Q(type__icontains=vuln_type)

    if vuln_name:
        main_query &= Q(name__icontains=vuln_name)

    return Vulnerability.objects.filter(main_query).select_related('subdomain', 'web_app')


@api.post("/webapps/", response=WebAppCreateOut)
def create_webapp(request, payload: WebAppCreateIn):
    raw_url = payload.url.strip()

    extracted = tldextract.extract(raw_url)
    parsed_url = urlparse(raw_url)

    if extracted.suffix:
        domain_name = f"{extracted.domain}.{extracted.suffix}"
    else:
        domain_name = extracted.domain

    hostname_parts = [extracted.subdomain, extracted.domain, extracted.suffix]
    hostname = ".".join(part for part in hostname_parts if part)

    scheme = parsed_url.scheme if parsed_url.scheme else "https"

    normalized_url = f"{scheme}://{hostname}"

    with transaction.atomic():

        if payload.target_name.isdigit():
            target_obj, _ = Target.objects.get_or_create(id=int(payload.target_name))
        else:
            target_obj, _ = Target.objects.get_or_create(name=payload.target_name.lower())

        domain_obj, _ = Domain.objects.get_or_create(
            hostname=domain_name,
            defaults={"target": target_obj}
        )

        subdomain_obj, _ = Subdomain.objects.get_or_create(
            hostname=hostname,
            defaults={"domain": domain_obj}
        )

        webapp_obj, _ = WebApplication.objects.get_or_create(
            url=normalized_url,
            defaults={"subdomain": subdomain_obj}
        )

    return {
        "message": "Successfully Created Webapp",
        "target_id": target_obj.id,
        "target": target_obj.name,
        "domain": domain_obj.hostname,
        "subdomain": subdomain_obj.hostname,
        "webapp_url": webapp_obj.url
    }