import os, subprocess



def get_agent_name():
    return os.environ["AGENT"]

def get_model_name():
    return os.environ["MODEL"]

agent_cmds = {
    "gemini": ["/usr/bin/gemini", "--yolo", "-m", get_model_name(), "-p"],
    "claude": ["/root/.local/bin/claude", "--dangerously-skip-permissions", "--model", get_model_name(), "-p"],
    "codex": ["/usr/bin/codex", "exec", "--dangerously-bypass-approvals-and-sandbox", "-m", get_model_name()],
}



def call_agent(prompt):
    """
    Takes a prompt and returns agent response.
    """

    agent = get_agent_name()
    model = get_model_name()

    cmd = agent_cmds[agent].copy()

    cmd.append(prompt)

    proc = subprocess.run(cmd, capture_output=True, text=True)

    return proc.stdout


if __name__ == "__main__":
    print(call_agent("What is ur name"))
