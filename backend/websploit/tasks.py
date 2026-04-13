import sys
import io
from celery import shared_task
from backend.core.recon.main import recon


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


@shared_task(bind=True)
def recon_task(self, domain, chunk_size=None):
    if chunk_size == '':
        chunk_size = None
    elif chunk_size is not None:
        chunk_size = int(chunk_size)

    old_stdout = sys.stdout
    capture = LogCapture(self)
    sys.stdout = capture

    try:
        result = recon(domain, chunk_size=chunk_size)

        return {'status': 'SUCCESS', 'result': result, 'logs': capture.logs}

    finally:
        sys.stdout = old_stdout