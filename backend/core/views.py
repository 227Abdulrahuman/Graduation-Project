from django.shortcuts import render, redirect,get_object_or_404
from django.db.models import Count, Q
from backend.core.models import *
from django.http import JsonResponse
from celery.result import AsyncResult
from backend.websploit.tasks import recon_task


def home_view(request):
    targets = Target.objects.annotate(
        domain_count=Count('domains', distinct=True),
        subdomain_count=Count('domains__subdomains', distinct=True),
        webapp_count=Count('domains__subdomains__webapps', distinct=True),
        vuln_count=Count('domains__subdomains__webapps__vulnerabilities', distinct=True),
        vuln_critical=Count('domains__subdomains__webapps__vulnerabilities',
                            filter=Q(domains__subdomains__webapps__vulnerabilities__severity='critical'), distinct=True),
        vuln_high=Count('domains__subdomains__webapps__vulnerabilities',
                        filter=Q(domains__subdomains__webapps__vulnerabilities__severity='high'), distinct=True),
        vuln_medium=Count('domains__subdomains__webapps__vulnerabilities',
                          filter=Q(domains__subdomains__webapps__vulnerabilities__severity='medium'), distinct=True),
        vuln_low=Count('domains__subdomains__webapps__vulnerabilities',
                       filter=Q(domains__subdomains__webapps__vulnerabilities__severity='low'), distinct=True),
    )
    return render(request, 'home.html', {'targets': targets})


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


def target_detail(request, pk):
    target = get_object_or_404(Target, pk=pk)

    # Traverse backwards from Subdomain -> Domain -> Target
    subdomains = Subdomain.objects.filter(domain__target=target).select_related('domain')

    # Traverse backwards from WebApp -> Subdomain -> Domain -> Target
    webapps = WebApplication.objects.filter(subdomain__domain__target=target).select_related('subdomain')

    context = {
        'target': target,
        'subdomains': subdomains,
        'webapps': webapps,
    }
    return render(request, 'target_detail.html', context)


def scan_recon(request):
    if request.method == 'POST':
        domain = request.POST.get('domain')
        chunk_size = request.POST.get('chunk_size')

        task = recon_task.delay(domain, chunk_size)
        return JsonResponse({'task_id': task.id})

    return render(request, 'scan_recon.html')


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