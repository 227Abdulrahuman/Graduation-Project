# Setup

### Clone the repo
`git clone https://github.com/227Abdulrahuman/Web-Sploit`
### Create .env file in the repo directory

```
CHAOS_KEY="" # Get it from https://chaos.projectdiscovery.io/
DIGITALYAMA_KEY="" # Get it from https://digitalyama.com/
SHODAN_KEY="" # Get it from https://www.shodan.io/
VIRUSTOTAL_KEY="" # Get it from https://www.virustotal.com/

#The AI agent that will be used for hacking example: AGENT="claude" MODEL="claude-sonnet-4-6"
# Supported AI Agents [codex, claude, deepcode=claude with deepseek API, xicode=claude with Xiaomi Mimo API]
AGENT=""
MODEL=""
IS_SANDBOX=1


XICODE_TOKEN="" #Xiaomi Mimo api key
DEEPCODE_TOKEN="" # Deepseek API Key

DJANGO_DEBUG=False
PYTHONUNBUFFERED=1
```


### Run container
`sudo docker compose up`
