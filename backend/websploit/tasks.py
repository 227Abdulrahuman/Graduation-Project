import sys
import io
import logging
from celery import shared_task
from backend.core.recon.main import recon
from backend.core.scan.webapp_analysis import analyze_webapp
from backend.core.utilities.webapp_manual import add_webapp_manually
from backend.core.scan.vuln_scan import vuln_scan
from backend.core.fuzzer.directory_fuzzer import directory_fuzz

# --- THIS IS YOUR EXISTING RECON LOGIC (UNTOUCHED) ---
class LogCapture(io.StringIO):
    def __init__(self, task):
        super().__init__()
        self.task = task
        self.task_id = task.request.id
        self.logs = []

    def write(self, text):
        text_clean = text.strip()
        if text_clean:
            self.logs.append(text_clean)
            self.task.update_state(
                task_id=self.task_id,
                state='PROGRESS',
                meta={'logs': self.logs}
            )

        sys.__stdout__.write(text)


# --- THIS IS THE MISSING CLASS FOR THE WEBAPP LOGIC ---
class CeleryTaskLogHandler(logging.Handler):
    def __init__(self, task):
        super().__init__()
        self.task = task
        self.logs = []

    def emit(self, record):
        msg = self.format(record)
        if any(marker in msg for marker in ["[*]", "[+]", "[-]"]):
            self.logs.append(msg)
            self.task.update_state(state='PROGRESS', meta={'logs': self.logs})
# ------------------------------------------------------


@shared_task(bind=True)
def recon_task(self, domain, chunk_size=None, multiplicity=3, providers=None):
    if chunk_size == '':
        chunk_size = None
    elif chunk_size is not None:
        chunk_size = int(chunk_size)

    if multiplicity == '':
        multiplicity = 3
    elif multiplicity is not None:
        multiplicity = int(multiplicity)

    if not providers:
        providers = None

    old_stdout = sys.stdout
    capture = LogCapture(self)
    sys.stdout = capture

    try:
        result = recon(domain, chunk_size=chunk_size, multiplicity=multiplicity, providers=providers)

        return {'status': 'SUCCESS', 'result': result, 'logs': capture.logs}

    finally:
        sys.stdout = old_stdout


@shared_task(bind=True)
def webapp_task(self, url, auth_headers=None, logout=None):
    # Hook into the logger
    logger = logging.getLogger()
    log_handler = CeleryTaskLogHandler(self)
    log_handler.setFormatter(logging.Formatter('%(message)s'))
    logger.addHandler(log_handler)

    try:
        # Run the webapp analysis
        result = analyze_webapp(url, auth_headers=auth_headers, logout=logout)

        # Return the result AND the final logs array
        return {'status': 'SUCCESS', 'result': result, 'logs': log_handler.logs}
    finally:
        # Clean up the logger when done
        logger.removeHandler(log_handler)


@shared_task(bind=True)
def vuln_scan_task(self, url, auth_headers=None, run_xss=True, run_sqli=True, run_open_redirect=True, run_path_traversal=True):
    old_stdout = sys.stdout
    capture = LogCapture(self)
    sys.stdout = capture

    try:
        result = vuln_scan(
            url,
            auth_headers=auth_headers,
            run_xss=run_xss,
            run_sqli=run_sqli,
            run_open_redirect=run_open_redirect,
            run_path_traversal=run_path_traversal,
        )
        return {'status': 'SUCCESS', 'result': result, 'logs': capture.logs}
    finally:
        sys.stdout = old_stdout


@shared_task(bind=True)
def add_webapp_manual_task(self, url):
    old_stdout = sys.stdout
    capture = LogCapture(self)
    sys.stdout = capture

    try:
        result = add_webapp_manually(url)
        return {'status': 'SUCCESS', 'result': result, 'logs': capture.logs}
    finally:
        sys.stdout = old_stdout


@shared_task(bind=True)
def add_subdomain_task(self, hostname, domain_id):
    """Run dnsx on a single hostname to resolve IP/CNAME and insert into DB."""
    import tempfile, json, subprocess, os

    old_stdout = sys.stdout
    capture = LogCapture(self)
    sys.stdout = capture

    try:
        from backend.core.models import Domain, Subdomain
        domain_obj = Domain.objects.get(id=domain_id)

        print(f"[*] Running dnsx on {hostname}")

        # Write hostname to a temp file for dnsx -l
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(hostname + '\n')
            temp_path = f.name

        output_file = tempfile.mktemp(suffix='.json')

        try:
            cmd = [
                'dnsx', '-l', temp_path,
                '-a', '-cname',
                '-silent', '-nc', '-resp',
                '-j', '-o', output_file
            ]
            subprocess.run(cmd, text=True, capture_output=True)

            results = []
            with open(output_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        resolved_host = data.get('host', hostname)
                        cname_list = data.get('cname')
                        a_list = data.get('a')

                        subdomain, created = Subdomain.objects.update_or_create(
                            domain=domain_obj,
                            hostname=resolved_host,
                            defaults={
                                "is_alive": True,
                                "cname": cname_list[-1] if cname_list else None,
                                "ip": a_list[0] if a_list else None,
                            }
                        )
                        results.append({
                            'hostname': subdomain.hostname,
                            'ip': subdomain.ip,
                            'cname': subdomain.cname,
                            'created': created,
                        })
                        print(f"[+] {'Added' if created else 'Updated'} subdomain: {subdomain.hostname} (IP: {subdomain.ip or 'N/A'}, CNAME: {subdomain.cname or 'N/A'})")
                    except Exception as e:
                        print(f"[-] Error processing dnsx output line: {e}")
        finally:
            os.unlink(temp_path)
            if os.path.exists(output_file):
                os.unlink(output_file)

        if not results:
            print(f"[-] dnsx returned no results for {hostname}")
        else:
            print(f"[+] Finished dnsx for {hostname}")

        return {'status': 'SUCCESS', 'result': results, 'logs': capture.logs}
    except Exception as e:
        print(f"[-] Error: {e}")
        return {'status': 'ERROR', 'result': str(e), 'logs': capture.logs}
    finally:
        sys.stdout = old_stdout


@shared_task(bind=True)
def dir_fuzz_task(self, url, wordlist):
    old_stdout = sys.stdout
    capture = LogCapture(self)
    sys.stdout = capture

    try:
        directory_fuzz(url, wordlist)
        return {'status': 'SUCCESS', 'result': None, 'logs': capture.logs}
    except Exception as e:
        print(f"[-] Error: {e}")
        return {'status': 'ERROR', 'result': str(e), 'logs': capture.logs}
    finally:
        sys.stdout = old_stdout


@shared_task(bind=True)
def add_webapp_task(self, url):
    """Run httpx on a single URL and insert WebApplication into DB."""
    import tempfile, json, subprocess, os
    from urllib.parse import urlparse

    old_stdout = sys.stdout
    capture = LogCapture(self)
    sys.stdout = capture

    try:
        from backend.core.models import Domain, Subdomain, WebApplication

        print(f"[*] Running httpx on {url}")

        # Write URL to a temp file for httpx -l
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(url + '\n')
            temp_path = f.name

        output_file = tempfile.mktemp(suffix='.json')

        try:
            cmd = [
                'httpx', '-l', temp_path,
                '-nc', '-silent',
                '-sc', '-title', '-location', '-td', '-cl',
                '-j', '-o', output_file,
            ]
            subprocess.run(cmd, text=True, capture_output=True)

            results = []
            with open(output_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        final_url = data.get('url', url)
                        hostname = data.get('input') or urlparse(final_url).hostname

                        if not hostname:
                            print(f"[-] Could not determine hostname from httpx output for {final_url}")
                            continue

                        # Find or create the Subdomain — try to match to a Domain
                        subdomain_obj = Subdomain.objects.filter(hostname=hostname).first()
                        if not subdomain_obj:
                            # Try to find a matching domain
                            domain_obj = None
                            for d in Domain.objects.all():
                                if hostname.endswith('.' + d.hostname) or hostname == d.hostname:
                                    domain_obj = d
                                    break
                            if not domain_obj:
                                print(f"[-] No matching domain found for hostname {hostname}. Creating subdomain requires a domain.")
                                continue
                            subdomain_obj = Subdomain.objects.create(
                                domain=domain_obj,
                                hostname=hostname,
                                is_alive=True,
                            )
                            print(f"[+] Created new subdomain: {hostname}")

                        webapp, created = WebApplication.objects.update_or_create(
                            subdomain=subdomain_obj,
                            url=final_url,
                            defaults={
                                "status_code": data.get('status_code'),
                                "content_length": data.get('content_length'),
                                "tech_stack": data.get('tech') or [],
                                "title": data.get('title'),
                                "location": data.get('location'),
                            }
                        )
                        results.append({
                            'url': webapp.url,
                            'status_code': webapp.status_code,
                            'title': webapp.title,
                            'created': created,
                        })
                        print(f"[+] {'Added' if created else 'Updated'} webapp: {webapp.url} (Status: {webapp.status_code})")
                    except Exception as e:
                        print(f"[-] Error processing httpx output line: {e}")
        finally:
            os.unlink(temp_path)
            if os.path.exists(output_file):
                os.unlink(output_file)

        if not results:
            print(f"[-] httpx returned no results for {url}")
        else:
            print(f"[+] Finished httpx for {url}")

        return {'status': 'SUCCESS', 'result': results, 'logs': capture.logs}
    except Exception as e:
        print(f"[-] Error: {e}")
        return {'status': 'ERROR', 'result': str(e), 'logs': capture.logs}
    finally:
        sys.stdout = old_stdout
