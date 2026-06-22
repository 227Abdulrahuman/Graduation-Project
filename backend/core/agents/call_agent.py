import os, subprocess, shlex


AGENT_CONFIGS = {
    "gemini": {
        "shell_cmd": "/usr/bin/gemini --yolo -m {model} -p {prompt}",
    },
    "claude": {
        "shell_cmd": "/root/.local/bin/claude --dangerously-skip-permissions --model {model} -p {prompt}",
    },
    "codex": {
        "shell_cmd": "/usr/bin/codex exec --dangerously-bypass-approvals-and-sandbox -m {model} {prompt}",
    },
    "xicode": {
        "shell_cmd": "xicode --dangerously-skip-permissions -p {prompt}",
    },
    "deepcode": {
        "shell_cmd": "deepcode --dangerously-skip-permissions -p {prompt}",
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

    proc = subprocess.run(
        ["bash", "-i", "-c", cmd_str],
        capture_output=True,
        text=True,
        env=os.environ,
    )

    return proc.stdout


def check_agent():
    agent = get_agent_name()

    if agent not in AGENT_CONFIGS:
        return False, f"Unknown agent: {agent}"

    try:
        result = call_agent("Respond with only the word OK")
    except KeyError as e:
        return False, f"Missing environment variable: {e}"
    except FileNotFoundError:
        return False, f"Agent binary not found for '{agent}'"
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