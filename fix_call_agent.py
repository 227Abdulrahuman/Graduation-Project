import os, subprocess

agent_cmds = {
    "gemini": ["gemini", "--yolo"],
    "claude": ["claude", "--dangerously-skip-permissions"],
    "codex": ["codex", "--dangerously-bypass-approvals-and-sandbox"],
}



def get_agent_name():
    return os.environ["AGENT"]

def get_model_name():
    return os.environ["MODEL"]



def call_agent(prompt):
    """
    Takes a prompt and returns agent response.
    """

    agent = get_agent_name()
    model = get_model_name()

    cmd = agent_cmds[agent].copy()

    cmd.append("-m")
    cmd.append(model)
    cmd.append("-p")
    cmd.append(prompt)

    proc = subprocess.run(cmd, capture_output=True, text=True)

    return proc.stdout


print(call_agent("What is 1+1"))
