import asyncio
import fcntl
import json
import os
import pty
import struct
import termios

from channels.generic.websocket import AsyncWebsocketConsumer
from django.conf import settings


class TerminalConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.master_fd = None
        self.process = None
        self._read_task = None
        await self.accept()

        agent_dir = str(settings.BASE_DIR.parent / 'agent')
        if not os.path.isdir(agent_dir):
            agent_dir = os.getcwd()

        master_fd, slave_fd = pty.openpty()
        self.master_fd = master_fd

        def _setup_pty():
            os.setsid()
            fcntl.ioctl(slave_fd, termios.TIOCSCTTY, 0)

        self.process = await asyncio.create_subprocess_exec(
            '/bin/bash',
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            cwd=agent_dir,
            env={**os.environ, 'TERM': 'xterm-256color'},
            preexec_fn=_setup_pty,
        )
        os.close(slave_fd)

        self._read_task = asyncio.ensure_future(self._forward_output())

    async def _forward_output(self):
        loop = asyncio.get_event_loop()
        while True:
            try:
                data = await loop.run_in_executor(None, os.read, self.master_fd, 4096)
                await self.send(bytes_data=data)
            except OSError:
                break
        await self.close()

    async def receive(self, text_data=None, bytes_data=None):
        if bytes_data and self.master_fd is not None:
            os.write(self.master_fd, bytes_data)
        elif text_data and self.master_fd is not None:
            try:
                msg = json.loads(text_data)
                if msg.get('type') == 'resize':
                    cols = int(msg.get('cols', 80))
                    rows = int(msg.get('rows', 24))
                    fcntl.ioctl(
                        self.master_fd,
                        termios.TIOCSWINSZ,
                        struct.pack('HHHH', rows, cols, 0, 0),
                    )
            except (json.JSONDecodeError, KeyError, ValueError, OSError):
                pass

    async def disconnect(self, close_code):
        if self._read_task:
            self._read_task.cancel()
        if self.process:
            try:
                self.process.terminate()
            except ProcessLookupError:
                pass
        if self.master_fd is not None:
            try:
                os.close(self.master_fd)
            except OSError:
                pass
            self.master_fd = None
