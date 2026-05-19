import os, subprocess

agent_cmds = {
    "gemini": ["gemini", "--yolo"],
}

def call_agent(prompt):
    os.environ["AGENT"] = "gemini"
    os.environ["MODEL"] = "gemini-2.5-flash"
    
    agent = os.environ["AGENT"]
    model = os.environ["MODEL"]

    cmd = agent_cmds[agent].copy()

    cmd.append("-m")
    cmd.append(model)
    cmd.append("-p")
    cmd.append(prompt)

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
        return "STDOUT: " + proc.stdout + "\nSTDERR: " + proc.stderr + "\nRETURNCODE: " + str(proc.returncode)
    except Exception as e:
        return "EXCEPTION: " + str(e)

print(call_agent("What is 1+1"))
