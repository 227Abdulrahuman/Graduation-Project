import os, subprocess



def get_agent_name():
    return os.environ["AGENT"]

def get_model_name():
    return os.environ["MODEL"]

agent_cmds = {
    "gemini": ["/usr/bin/gemini", "--yolo", "-m", get_model_name(), "-p"],
    "claude": ["/root/.local/bin/claude", "--dangerously-skip-permissions", "--model", get_model_name(), "-p"],
    "codex": ["/usr/bin/codex", "exec", "--dangerously-bypass-approvals-and-sandbox", "-m", get_model_name()],
    "xicode" : ["xicode", "--dangerously-skip-permissions", "-p"]
}



def call_agent(prompt):
    """
    Takes a prompt and returns agent response.
    """

    agent = get_agent_name()

    cmd = agent_cmds[agent].copy()

    cmd.append(prompt)

    proc = subprocess.run(cmd, capture_output=True, text=True)

    return proc.stdout


def check_agent():
    """
    Verifies the agent is reachable and responding correctly.
    Returns (True, response) on success or (False, error_message) on failure.
    """
    agent = get_agent_name()

    if agent not in agent_cmds:
        return False, f"Unknown agent: {agent}"

    try:
        result = call_agent("Respond with only the word OK")
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
