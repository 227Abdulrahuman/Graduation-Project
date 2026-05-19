import os
import shlex
import subprocess

from dotenv import load_dotenv

load_dotenv()


DEFAULT_AGENT = "gemini"
SUPPORTED_AGENTS = {"gemini", "claude", "codex"}


def get_ai_agent_name():
    agent = os.getenv("AI_AGENT", DEFAULT_AGENT).strip().lower()
    if agent not in SUPPORTED_AGENTS:
        print(f"Unsupported AI_AGENT '{agent}', falling back to {DEFAULT_AGENT}")
        return DEFAULT_AGENT
    return agent


def get_ai_agent_display_name():
    return get_ai_agent_name().title()


def build_ai_agent_command(prompt):
    custom_command = os.getenv("AI_AGENT_COMMAND", "").strip()
    if custom_command:
        return shlex.split(custom_command) + [prompt]

    agent = get_ai_agent_name()

    if agent == "gemini":
        model = os.getenv("AI_AGENT_MODEL", os.getenv("GEMINI_MODEL", "gemini-3-flash-preview"))
        command = [os.getenv("GEMINI_BIN", "gemini"), "-p", prompt]
        if model:
            command.extend(["-m", model])
        return command

    if agent == "claude":
        return [
            os.getenv("CLAUDE_BIN", "/root/.local/bin/claude"),
            "-p",
            prompt,
            "--dangerously-skip-permissions",
        ]

    return [os.getenv("CODEX_BIN", "codex"), "exec", prompt]


def run_ai_agent(prompt):
    env = {**os.environ, "IS_SANDBOX": "1"}
    return subprocess.run(
        build_ai_agent_command(prompt),
        capture_output=True,
        text=True,
        check=True,
        env=env,
    )
