import os, subprocess
from pathlib import Path

def init_notify():
    config_dir = "/root/.config/notify"
    os.makedirs(config_dir, exist_ok=True)

    config_file = Path(f"{config_dir}/provider-config.yaml")

    if not config_file.exists():
        bot_url = os.getenv("DISCORD_BOT")
        temp = "{{data}}"
        with open(config_file, 'w') as file:
            file.write(f"""discord:
     - id: 'hunter'
       discord_channel: 'hunt_bot'
       discord_username: '07abdulrahman'
       discord_format: '{temp}'
       discord_webhook_url: '{bot_url}'""")
    pass

def notify_discord(message):
    init_notify()

    subprocess.run(
        ["notify", "-id", "hunter"],
        input=message,
        capture_output=True,
        text=True
    )
    pass
