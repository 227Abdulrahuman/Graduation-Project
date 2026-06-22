import os, subprocess, shlex


CLAUDE_BIN = "/root/.local/bin/claude"

AGENT_CONFIGS = {
    "gemini": {
        "shell_cmd": "/usr/bin/gemini --yolo -m {model} -p {prompt}",
    },
    "claude": {
        "shell_cmd": f"{CLAUDE_BIN} --dangerously-skip-permissions --model {{model}} -p {{prompt}}",
    },
    "codex": {
        "shell_cmd": "/usr/bin/codex exec --dangerously-bypass-approvals-and-sandbox -m {model} {prompt}",
    },
    "xicode": {
        "shell_cmd": f"{CLAUDE_BIN} --dangerously-skip-permissions -p {{prompt}}",
        "env": lambda: {
            "ANTHROPIC_BASE_URL": "https://token-plan-sgp.xiaomimimo.com/anthropic",
            "ANTHROPIC_AUTH_TOKEN": os.environ["XICODE_TOKEN"],
            "ANTHROPIC_MODEL": "mimo-v2.5-pro[1m]",
            "ANTHROPIC_DEFAULT_OPUS_MODEL": "mimo-v2.5-pro[1m]",
            "ANTHROPIC_DEFAULT_SONNET_MODEL": "mimo-v2.5-pro[1m]",
            "ANTHROPIC_DEFAULT_HAIKU_MODEL": "mimo-v2.5-pro[1m]",
            "CLAUDE_CODE_SUBAGENT_MODEL": "mimo-v2.5-pro[1m]",
            "CLAUDE_CODE_EFFORT_LEVEL": "max",
        },
    },
    "deepcode": {
        "shell_cmd": f"{CLAUDE_BIN} --dangerously-skip-permissions -p {{prompt}}",
        "env": lambda: {
            "ANTHROPIC_BASE_URL": "https://api.deepseek.com/anthropic",
            "ANTHROPIC_AUTH_TOKEN": os.environ["DEEPCODE_TOKEN"],
            "ANTHROPIC_MODEL": "deepseek-v4-pro[1m]",
            "ANTHROPIC_DEFAULT_OPUS_MODEL": "deepseek-v4-pro[1m]",
            "ANTHROPIC_DEFAULT_SONNET_MODEL": "deepseek-v4-pro[1m]",
            "ANTHROPIC_DEFAULT_HAIKU_MODEL": "deepseek-v4-flash",
            "CLAUDE_CODE_SUBAGENT_MODEL": "deepseek-v4-flash",
            "CLAUDE_CODE_EFFORT_LEVEL": "max",
        },
    },
}


def get_agent_name():
    return os.environ["AGENT"]

def get_model_name():
    return os.environ.get("MODEL", "")


def call_agent(prompt):
    agent = get_agent_name()

    if agent not in AGENT_CONFIGS:
        raise ValueError(f"Unknown agent: {agent}")

    config = AGENT_CONFIGS[agent]

    cmd_str = config["shell_cmd"].format(
        model=shlex.quote(get_model_name()),
        prompt=shlex.quote(prompt),
    )

    env = dict(os.environ)
    if "env" in config:
        env.update(config["env"]())

    proc = subprocess.run(
        ["bash", "-c", cmd_str],
        capture_output=True,
        text=True,
        env=env,
        timeout=600,
    )

    if proc.returncode != 0 and not proc.stdout.strip():
        raise RuntimeError(f"Agent exited with code {proc.returncode}: {proc.stderr.strip()}")

    return proc.stdout


def check_agent():
    try:
        agent = get_agent_name()
    except KeyError:
        return False, "AGENT environment variable is not set"

    if agent not in AGENT_CONFIGS:
        return False, f"Unknown agent: {agent}"

    try:
        result = call_agent("Respond with only the word OK")
    except KeyError as e:
        return False, f"Missing environment variable: {e}"
    except FileNotFoundError:
        return False, f"Agent binary not found for '{agent}'"
    except subprocess.TimeoutExpired:
        return False, f"Agent timed out"
    except Exception as e:
        return False, f"Agent call failed: {e}"

    if not result or not result.strip():
        return False, "Agent returned empty response"

    return True, result.strip()


if __name__ == "__main__":
    ok, msg = check_agent()
    if ok:
        print(f"Agent is working. Response: {msg}")
    else:
        print(f"Agent check failed: {msg}")