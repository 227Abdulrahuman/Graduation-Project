import sys
import io
import logging
from celery import shared_task
from backend.core.recon.main import recon
from backend.core.scan.webapp_analysis import analyze_webapp
from backend.core.utilities.webapp_manual import add_webapp_manually
from backend.core.scan.vuln_scan import vuln_scan

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
