from django.shortcuts import render, redirect,get_object_or_404
from django.db.models import Count, Q
from backend.core.models import *
from celery.result import AsyncResult
from backend.websploit.tasks import recon_task
from django.core.paginator import Paginator
from django.http import JsonResponse
from django.views.decorators.http import require_POST
import os

from django.shortcuts import render
from django.db.models import Count, Q, F
from backend.core.models import Target

from django.shortcuts import render, redirect, get_object_or_404
from django.db.models import Count, Q
from django.db.models.functions import Coalesce
from backend.core.models import *


def home_view(request):
    # 1. Base annotations for the domains, subdomains, and web apps
    targets_qs = Target.objects.annotate(
        domain_count=Count('domains', distinct=True),
        subdomain_count=Count('domains__subdomains', distinct=True),
        webapp_count=Count('domains__subdomains__webapps', distinct=True),
    )

    # Evaluate the queryset into a list so we can dynamically attach properties
    target_list = list(targets_qs)
    target_dict = {t.id: t for t in target_list}

    # Initialize zero-state counters for all targets
    for t in target_list:
        t.vuln_count = 0
        t.vuln_critical = 0
        t.vuln_high = 0
        t.vuln_medium = 0
        t.vuln_low = 0

    # 2. Fetch all vulnerabilities and dynamically climb the hierarchy to find their Target ID
    vulns = Vulnerability.objects.annotate(
        resolved_target_id=Coalesce(
            'web_app__subdomain__domain__target_id',
            'endpoint__web_app__subdomain__domain__target_id',
            'parameter__endpoint__web_app__subdomain__domain__target_id'
        )
    ).filter(resolved_target_id__in=target_dict.keys()).values('resolved_target_id', 'severity')

    # 3. Tally them up safely in Python (ignoring case sensitivity)
    for v in vulns:
        t_id = v['resolved_target_id']
        sev = (v['severity'] or '').lower()

        if t_id in target_dict:
            target_dict[t_id].vuln_count += 1
            if sev == 'critical':
                target_dict[t_id].vuln_critical += 1
            elif sev == 'high':
                target_dict[t_id].vuln_high += 1
            elif sev == 'medium':
                target_dict[t_id].vuln_medium += 1
            elif sev == 'low':
                target_dict[t_id].vuln_low += 1

    return render(request, 'home.html', {'targets': target_list})


def webapps_list(request):
    # Only get analyzed web apps
    apps = WebApplication.objects.filter(analyzed=True).select_related('subdomain__domain__target')

    # Filtering logic
    target_id = request.GET.get('target')
    domain_id = request.GET.get('domain')
    title_search = request.GET.get('title', '').strip()

    if target_id and target_id != 'all':
        apps = apps.filter(subdomain__domain__target_id=target_id)
    if domain_id and domain_id != 'all':
        apps = apps.filter(subdomain__domain_id=domain_id)
    if title_search:
        apps = apps.filter(title__icontains=title_search)

    # For filter dropdowns
    targets = Target.objects.all()

    if target_id and target_id != 'all':
        domains = Domain.objects.filter(target_id=target_id)
    else:
        domains = Domain.objects.all()

    context = {
        'apps': apps,
        'targets': targets,
        'domains': domains,
        'selected_target': target_id,
        'selected_domain': domain_id,
        'title_search': title_search,
    }
    return render(request, 'webapps_list.html', context)


def add_webapp_manual(request):
    if request.method == 'POST':
        url = request.POST.get('url')
        if url:
            task = add_webapp_manual_task.delay(url)
            return JsonResponse({'task_id': task.id})
    return JsonResponse({'error': 'Invalid request'}, status=400)


def target_add(request):

    if request.method == 'POST':
        name = request.POST.get('name')
        target_type = request.POST.get('type')
        platform = request.POST.get('platform')
        program_url = request.POST.get('program_url')
        domains_raw = request.POST.get('domains')  # Get the raw text area input

        if name:
            # Create the Target
            target = Target.objects.create(
                name=name,
                type=target_type,
                platform=platform,
                program_url=program_url
            )

            # Process and attach domains if any were provided
            if domains_raw:
                # Split by newlines to allow pasting multiple domains
                domain_lines = domains_raw.splitlines()
                for line in domain_lines:
                    hostname = line.strip()
                    if hostname:
                        # Create a Domain linked to this specific Target
                        Domain.objects.create(target=target, hostname=hostname)

            return redirect('home')

    return render(request, 'target_add.html')



def target_delete(request, pk):
    # Ensure it's a POST request for security so users can't delete by just typing the URL
    if request.method == 'POST':
        target = get_object_or_404(Target, pk=pk)
        target.delete()
    return redirect('home') # Adjust 'home' if your URL name is different


# --- UPDATED: Target Detail View ---
def target_detail(request, pk):
    target = get_object_or_404(Target, pk=pk)

    # Get unique ports dynamically for the dropdown
    ports = Port.objects.filter(subdomain__domain__target=target).values_list('number', flat=True).distinct()
    available_ports = sorted([p for p in ports if p is not None])

    # Notice we removed subdomains and webapps from here to save memory!
    context = {
        'target': target,
        'available_ports': available_ports,
    }
    return render(request, 'target_detail.html', context)


# --- NEW: Backend API for Subdomains ---
def api_target_subdomains(request, pk):
    target = get_object_or_404(Target, pk=pk)
    subs = Subdomain.objects.filter(domain__target=target).select_related('domain').prefetch_related('ports')

    # Apply Filters
    domain_filter = request.GET.get('domain', 'all')
    if domain_filter != 'all':
        subs = subs.filter(domain__hostname=domain_filter)

    ip_filter = request.GET.get('ip', 'all')
    if ip_filter == 'yes':
        subs = subs.exclude(ip__isnull=True).exclude(ip__exact='')
    elif ip_filter == 'no':
        subs = subs.filter(Q(ip__isnull=True) | Q(ip__exact=''))

    cname_filter = request.GET.get('cname', 'all')
    if cname_filter == 'yes':
        subs = subs.exclude(cname__isnull=True).exclude(cname__exact='')
    elif cname_filter == 'no':
        subs = subs.filter(Q(cname__isnull=True) | Q(cname__exact=''))

    host_search = request.GET.get('host', '').strip()
    if host_search:
        subs = subs.filter(hostname__icontains=host_search)

    port_search = request.GET.get('port', 'all')
    if port_search != 'all':
        subs = subs.filter(ports__number=port_search)
        service_search = request.GET.get('service', '').strip()
        if service_search:
            subs = subs.filter(ports__service__icontains=service_search)

    # Distinct and order for consistent pagination
    subs = subs.distinct().order_by('hostname')

    # Paginate
    paginator = Paginator(subs, 500)
    page_num = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_num)

    # Serialize
    data = []
    for s in page_obj:
        ports_data = []
        for p in s.ports.all():
            p_str = str(p.number)
            if p.service:
                p_str += f"/{p.service}"
            ports_data.append(p_str)

        data.append({
            'hostname': s.hostname,
            'domain': s.domain.hostname,
            'ip': s.ip,
            'cname': s.cname,
            'ports': ports_data
        })

    return JsonResponse({
        'results': data,
        'total_pages': paginator.num_pages,
        'current_page': page_obj.number,
        'total_count': paginator.count
    })


# --- NEW: Backend API for Web Apps ---
def api_target_webapps(request, pk):
    target = get_object_or_404(Target, pk=pk)
    apps = WebApplication.objects.filter(subdomain__domain__target=target).select_related('subdomain__domain')

    # Apply Filters
    domain_filter = request.GET.get('domain', 'all')
    if domain_filter != 'all':
        apps = apps.filter(subdomain__domain__hostname=domain_filter)

    host_search = request.GET.get('host', '').strip()
    if host_search:
        apps = apps.filter(Q(subdomain__hostname__icontains=host_search) | Q(url__icontains=host_search))

    tech_search = request.GET.get('tech', '').strip()
    if tech_search:
        apps = apps.filter(tech_stack__icontains=tech_search)

    title_search = request.GET.get('title', '').strip()
    if title_search:
        apps = apps.filter(title__icontains=title_search)

    status_search = request.GET.get('status', '').strip()
    if status_search:
        apps = apps.filter(status_code__icontains=status_search)

    tested_filter = request.GET.get('tested', 'all')
    if tested_filter == 'yes':
        apps = apps.filter(tested=True)
    elif tested_filter == 'no':
        apps = apps.filter(tested=False)

    # Sorting
    sort_order = request.GET.get('sort', 'desc')
    if sort_order == 'asc':
        apps = apps.order_by('status_code', 'url')
    else:
        apps = apps.order_by('-status_code', 'url')

    # Paginate
    paginator = Paginator(apps, 500)
    page_num = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_num)

    # Serialize
    data = []
    for a in page_obj:
        data.append({
            'id': a.id,
            'url': a.url,
            'status_code': a.status_code,
            'title': a.title,
            'content_length': a.content_length,
            'tech_stack': a.tech_stack or [],
            'tested': a.tested,
        })

    return JsonResponse({
        'results': data,
        'total_pages': paginator.num_pages,
        'current_page': page_obj.number,
        'total_count': paginator.count
    })


@require_POST
def api_webapp_toggle_tested(request, pk):
    webapp = get_object_or_404(WebApplication, pk=pk)
    webapp.tested = not webapp.tested
    webapp.save(update_fields=['tested'])
    return JsonResponse({'tested': webapp.tested})


import os
from backend.core.recon.passive_recon import PROVIDERS as RECON_PROVIDERS

def _provider_meta():
    """Strip the func reference before passing providers to a template."""
    return [{"id": p["id"], "name": p["name"], "auth": p["auth"]} for p in RECON_PROVIDERS]

def scan_recon(request):
    if request.method == 'POST':
        domain = request.POST.get('domain')
        chunk_size = request.POST.get('chunk_size')
        multiplicity = request.POST.get('multiplicity')
        cookie_content = request.POST.get('cookie_content')
        providers = request.POST.getlist('providers') or None

        if cookie_content and cookie_content.strip():
            os.makedirs('/work/resources/securitytrails', exist_ok=True)
            with open('/work/resources/securitytrails/cookie.txt', 'w') as f:
                f.write(cookie_content.strip())

        task = recon_task.delay(domain, chunk_size=chunk_size, multiplicity=multiplicity, providers=providers)
        return JsonResponse({'task_id': task.id})

    return render(request, 'scan_recon.html', {'providers': _provider_meta()})


def check_task_status(request, task_id):
    task = AsyncResult(task_id)
    response_data = {'state': task.state}

    if task.state == 'PROGRESS':
        # Grab the live logs from the meta dict we set in LogCapture
        response_data['logs'] = task.info.get('logs', [])

    elif task.state == 'SUCCESS':
        # Task returned our custom dict {'status': 'SUCCESS', 'result': ..., 'logs': ...}
        response_data['result'] = task.result.get('result')
        response_data['logs'] = task.result.get('logs', [])

    elif task.state == 'FAILURE':
        response_data['error'] = str(task.info)

    return JsonResponse(response_data)

def target_edit(request, pk):
    if request.method == 'POST':
        target = get_object_or_404(Target, pk=pk)

        # 1. Update basic target info
        name = request.POST.get('name')
        if name:
            target.name = name

        target.type = request.POST.get('type')
        target.platform = request.POST.get('platform')
        target.program_url = request.POST.get('program_url')

        target.save()

        # 2. Handle Domains (Add/Remove)
        domains_raw = request.POST.get('domains')
        if domains_raw is not None:
            # Clean up the submitted list into a set of lowercase strings
            submitted_domains = {
                line.strip().lower()
                for line in domains_raw.splitlines()
                if line.strip()
            }

            # Get the currently saved domains for this target
            existing_domain_objs = target.domains.all()
            existing_domain_names = {d.hostname.lower() for d in existing_domain_objs}

            # Find domains to ADD (in submitted, but not in existing)
            domains_to_add = submitted_domains - existing_domain_names
            for d_name in domains_to_add:
                Domain.objects.create(target=target, hostname=d_name)

            # Find domains to REMOVE (in existing, but not in submitted)
            domains_to_remove = existing_domain_names - submitted_domains
            if domains_to_remove:
                # Because of your models.CASCADE setup, deleting these will
                # also automatically clean up related Subdomains and WebApps
                target.domains.filter(hostname__in=domains_to_remove).delete()

    return redirect('home')


from backend.websploit.tasks import webapp_task, add_webapp_manual_task


def scan_webapp(request):
    if request.method == 'POST':
        url = request.POST.get('url')
        logout = request.POST.get('logout')
        auth_headers_raw = request.POST.get('auth_headers')

        # Convert the textarea input into a list of strings
        auth_headers = []
        if auth_headers_raw:
            auth_headers = [
                line.strip()
                for line in auth_headers_raw.splitlines()
                if line.strip()
            ]

        # If logout is empty string, set to None
        if not logout:
            logout = None

        task = webapp_task.delay(url, auth_headers=auth_headers, logout=logout)
        return JsonResponse({'task_id': task.id})

    return render(request, 'scan_webapp.html')


def get_webapp_counts(webapp):
    return {
        'endpoints': webapp.endpoint.count(),
        'js_files': webapp.js_files.count(),
        'archives': webapp.subdomain.ArchivedURLs.count(),
        'client_routes': webapp.client_side_routes.count(),
    }


def webapp_detail(request, pk):
    webapp = get_object_or_404(WebApplication, pk=pk)
    endpoints = webapp.endpoint.all().prefetch_related('parameter')
    
    context = {
        'webapp': webapp,
        'endpoints': endpoints,
        'counts': get_webapp_counts(webapp),
        'active_tab': 'endpoints',
    }
    return render(request, 'webapp_endpoints.html', context)


def webapp_js_files(request, pk):
    webapp = get_object_or_404(WebApplication, pk=pk)
    js_files = list(webapp.js_files.values_list('name', flat=True))
    
    if not js_files:
        # Fallback for legacy filesystem files
        subdomain = webapp.subdomain.hostname
        clean_webapp_url = webapp.url.replace("://", "_").replace("/", "_").replace(".", "_").replace(":", "_")
        js_dir = os.path.join('/work', 'output', subdomain, clean_webapp_url, 'js')
        if os.path.exists(js_dir):
            js_files = [f for f in os.listdir(js_dir) if f.endswith('.js')]

    context = {
        'webapp': webapp,
        'js_files': sorted(js_files),
        'counts': get_webapp_counts(webapp),
        'active_tab': 'js_files',
    }
    return render(request, 'webapp_js_files.html', context)


def webapp_archives(request, pk):
    webapp = get_object_or_404(WebApplication, pk=pk)
    archived_urls = webapp.subdomain.ArchivedURLs.all()
    
    context = {
        'webapp': webapp,
        'archived_urls': archived_urls,
        'counts': get_webapp_counts(webapp),
        'active_tab': 'archives',
    }
    return render(request, 'webapp_archives.html', context)


def webapp_client_routes(request, pk):
    webapp = get_object_or_404(WebApplication, pk=pk)
    client_routes = webapp.client_side_routes.all()
    
    context = {
        'webapp': webapp,
        'client_routes': client_routes,
        'counts': get_webapp_counts(webapp),
        'active_tab': 'client_routes',
    }
    return render(request, 'webapp_client_routes.html', context)


def webapp_delete(request, pk):
    if request.method == 'POST':
        webapp = get_object_or_404(WebApplication, pk=pk)
        
        # Delete associated data generated during analysis
        webapp.endpoint.all().delete()
        webapp.js_files.all().delete()
        webapp.client_side_routes.all().delete()
        webapp.vulnerabilities.all().delete()
        
        # ArchivedURLs are linked to the subdomain
        webapp.subdomain.ArchivedURLs.all().delete()
        
        # Reset analyzed state instead of deleting the webapp
        webapp.analyzed = False
        webapp.save()
        
    return redirect('webapps_list')


def view_js_file(request, pk):
    webapp = get_object_or_404(WebApplication, pk=pk)
    filename = request.GET.get('filename')
    
    if not filename:
        return JsonResponse({'error': 'No filename provided'}, status=400)

    # Try database first
    js_obj = webapp.js_files.filter(name=filename).first()
    if js_obj:
        return JsonResponse({'content': js_obj.content, 'filename': filename})

    # Fallback to filesystem
    subdomain = webapp.subdomain.hostname
    clean_webapp_url = webapp.url.replace("://", "_").replace("/", "_").replace(".", "_").replace(":", "_")
    js_dir = os.path.join('/work', 'output', subdomain, clean_webapp_url, 'js')
    file_path = os.path.join(js_dir, filename)

    if not os.path.realpath(file_path).startswith(os.path.realpath(js_dir)):
        return JsonResponse({'error': 'Invalid file path'}, status=403)

    if not os.path.exists(file_path):
        return JsonResponse({'error': 'File not found'}, status=404)

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        return JsonResponse({'content': content, 'filename': filename})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


def js_viewer(request, pk):
    webapp = get_object_or_404(WebApplication, pk=pk)
    filename = request.GET.get('filename')

    if not filename:
        return redirect('webapp_detail', pk=pk)

    # Try database first
    js_obj = webapp.js_files.filter(name=filename).first()
    if js_obj:
        content = js_obj.content
    else:
        # Fallback to filesystem
        subdomain = webapp.subdomain.hostname
        clean_webapp_url = webapp.url.replace("://", "_").replace("/", "_").replace(".", "_").replace(":", "_")
        js_dir = os.path.join('/work', 'output', subdomain, clean_webapp_url, 'js')
        file_path = os.path.join(js_dir, filename)

        if os.path.realpath(file_path).startswith(os.path.realpath(js_dir)) and os.path.exists(file_path):
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
            except:
                content = "Error reading file content."
        else:
            return redirect('webapp_detail', pk=pk)

    context = {
        'webapp': webapp,
        'filename': filename,
        'content': content,
    }
    return render(request, 'js_viewer.html', context)


_summary_in_progress = set()

def js_summary(request, pk):
    webapp = get_object_or_404(WebApplication, pk=pk)
    filename = request.GET.get('filename')

    if not filename:
        return redirect('webapp_detail', pk=pk)

    js_obj = webapp.js_files.filter(name=filename).first()
    if not js_obj:
        return redirect('webapp_detail', pk=pk)

    if not js_obj.usage_summary:
        key = f"{pk}:{filename}"
        if key not in _summary_in_progress:
            import threading
            from backend.core.js_analysis.usage_summary import generate_usage_summary
            _summary_in_progress.add(key)
            def _run():
                try:
                    generate_usage_summary(webapp.url, filename)
                finally:
                    _summary_in_progress.discard(key)
            threading.Thread(target=_run, daemon=True).start()

        return render(request, 'js_summary.html', {
            'webapp': webapp,
            'filename': filename,
            'generating': True,
        })

    return render(request, 'js_summary.html', {
        'webapp': webapp,
        'filename': filename,
        'summary_content': js_obj.usage_summary,
    })


def js_summary_status(request, pk):
    from django.http import JsonResponse
    webapp = get_object_or_404(WebApplication, pk=pk)
    filename = request.GET.get('filename')
    js_obj = webapp.js_files.filter(name=filename).first()
    if js_obj and js_obj.usage_summary:
        return JsonResponse({'status': 'ready', 'content': js_obj.usage_summary})
    return JsonResponse({'status': 'generating'})


_routes_in_progress = set()

def js_routes(request, pk):
    webapp = get_object_or_404(WebApplication, pk=pk)
    filename = request.GET.get('filename')

    if not filename:
        return redirect('webapp_detail', pk=pk)

    js_obj = webapp.js_files.filter(name=filename).first()
    if not js_obj:
        return redirect('webapp_detail', pk=pk)

    if not js_obj.routes_analysis:
        key = f"{pk}:{filename}"
        if key not in _routes_in_progress:
            import threading
            from backend.core.js_analysis.routes_analysis import analyze_routes
            _routes_in_progress.add(key)
            def _run():
                try:
                    analyze_routes(webapp.url, filename)
                finally:
                    _routes_in_progress.discard(key)
            threading.Thread(target=_run, daemon=True).start()

        return render(request, 'js_routes.html', {
            'webapp': webapp,
            'filename': filename,
            'generating': True,
        })

    return render(request, 'js_routes.html', {
        'webapp': webapp,
        'filename': filename,
        'routes_content': js_obj.routes_analysis,
    })


def js_routes_status(request, pk):
    from django.http import JsonResponse
    webapp = get_object_or_404(WebApplication, pk=pk)
    filename = request.GET.get('filename')
    js_obj = webapp.js_files.filter(name=filename).first()
    if js_obj and js_obj.routes_analysis:
        return JsonResponse({'status': 'ready', 'content': js_obj.routes_analysis})
    return JsonResponse({'status': 'generating'})


_code_review_in_progress = set()

def js_code_review(request, pk):
    webapp = get_object_or_404(WebApplication, pk=pk)
    filename = request.GET.get('filename')

    if not filename:
        return redirect('webapp_detail', pk=pk)

    js_obj = webapp.js_files.filter(name=filename).first()
    if not js_obj:
        return redirect('webapp_detail', pk=pk)

    if not js_obj.code_review:
        key = f"{pk}:{filename}"
        if key not in _code_review_in_progress:
            import threading
            from backend.core.js_analysis.code_review import review_code
            _code_review_in_progress.add(key)
            def _run():
                try:
                    review_code(webapp.url, filename)
                finally:
                    _code_review_in_progress.discard(key)
            threading.Thread(target=_run, daemon=True).start()

        return render(request, 'js_code_review.html', {
            'webapp': webapp,
            'filename': filename,
            'generating': True,
        })

    return render(request, 'js_code_review.html', {
        'webapp': webapp,
        'filename': filename,
        'code_review_content': js_obj.code_review,
    })


def js_code_review_status(request, pk):
    from django.http import JsonResponse
    webapp = get_object_or_404(WebApplication, pk=pk)
    filename = request.GET.get('filename')
    js_obj = webapp.js_files.filter(name=filename).first()
    if js_obj and js_obj.code_review:
        return JsonResponse({'status': 'ready', 'content': js_obj.code_review})
    return JsonResponse({'status': 'generating'})

from backend.websploit.tasks import general_scan_task

def scan_general(request):
    if request.method == 'POST':
        domain = request.POST.get('domain')

        # Trigger the Celery task
        task = general_scan_task.delay(domain)
        return JsonResponse({'task_id': task.id})

    return render(request, 'scan_general.html')


def cancel_task(request, task_id):
    if request.method == 'POST':
        task = AsyncResult(task_id)
        # terminate=True forcefully kills the worker process executing the task
        task.revoke(terminate=True)
        return JsonResponse({'status': 'success', 'message': 'Task cancelled'})

    return JsonResponse({'status': 'error', 'message': 'Invalid request method'}, status=400)


def api_target_vulnerabilities(request, pk):
    target = get_object_or_404(Target, pk=pk)

    # Use Q objects to find vulns attached at ANY level (WebApp, EndPoint, or Parameter)
    vulns = Vulnerability.objects.filter(
        Q(web_app__subdomain__domain__target=target) |
        Q(endpoint__web_app__subdomain__domain__target=target) |
        Q(parameter__endpoint__web_app__subdomain__domain__target=target)
    ).select_related(
        'web_app',
        'endpoint__web_app',
        'parameter__endpoint__web_app'
    ).distinct()

    # Apply Severity Filter
    severity_filter = request.GET.get('severity', 'all').lower()
    if severity_filter != 'all':
        vulns = vulns.filter(severity__iexact=severity_filter)

    # Apply Search Filter
    search_query = request.GET.get('search', '').strip()
    if search_query:
        vulns = vulns.filter(name__icontains=search_query)

    # Order the results
    vulns = vulns.order_by('name')

    # Paginate
    paginator = Paginator(vulns, 500)
    page_num = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_num)

    # Serialize Data for JSON Response
    data = []
    for v in page_obj:
        # Dynamically resolve hierarchy upwards
        resolved_web_app = "—"
        resolved_endpoint = "—"
        resolved_param = "—"

        if v.parameter:
            resolved_param = v.parameter.key
            if v.parameter.endpoint:
                resolved_endpoint = v.parameter.endpoint.path
                if v.parameter.endpoint.web_app:
                    resolved_web_app = v.parameter.endpoint.web_app.url
        elif v.endpoint:
            resolved_endpoint = v.endpoint.path
            if v.endpoint.web_app:
                resolved_web_app = v.endpoint.web_app.url
        elif v.web_app:
            resolved_web_app = v.web_app.url

        data.append({
            'name': v.name,
            'severity': v.severity,
            'web_app': resolved_web_app,
            'endpoint': resolved_endpoint,
            'parameter': resolved_param
        })

    return JsonResponse({
        'results': data,
        'total_pages': paginator.num_pages,
        'current_page': page_obj.number,
        'total_count': paginator.count
    })


from backend.websploit.tasks import comprehensive_task


def scan_comprehensive(request):
    if request.method == 'POST':
        url = request.POST.get('url')
        logout = request.POST.get('logout')
        auth_headers_raw = request.POST.get('auth_headers')

        # Convert the textarea input into a list of strings
        auth_headers = []
        if auth_headers_raw:
            auth_headers = [
                line.strip()
                for line in auth_headers_raw.splitlines()
                if line.strip()
            ]

        # If logout is empty string, set to None
        if not logout:
            logout = None

        task = comprehensive_task.delay(url, auth_headers=auth_headers, logout=logout)
        return JsonResponse({'task_id': task.id})

    return render(request, 'scan_comprehensive.html')