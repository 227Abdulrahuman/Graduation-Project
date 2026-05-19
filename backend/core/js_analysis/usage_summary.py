#Connect to Django
import os, django, subprocess
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backend.websploit.settings")
django.setup()
from backend.core.models import *


def generate_usage_summary(webapp_url, js_filename):

    #Get Output Directory
    webapp = WebApplication.objects.get(url=webapp_url)
    subdomain = webapp.subdomain.hostname
    clean_webapp_url = webapp_url.replace("://", "_").replace("/", "_").replace(".", "_").replace(":", "_")
    output_dir = os.path.join('/work', 'output', subdomain, clean_webapp_url, 'js')
    os.makedirs(output_dir, exist_ok=True)


    # Prepare Prompt
    prompt = f"Explain the purpose of this JS file {output_dir}/{js_filename} The output directory of .md file is {output_dir}"

    claude_bin = "/root/.local/bin/claude"
    subprocess.run([claude_bin, "-p", prompt, "--dangerously-skip-permissions" ], capture_output=True, text=True, check=True, env={**os.environ, "IS_SANDBOX": "1"})

    #Store the summary Usage in the database.
    js_basename = os.path.splitext(js_filename)[0]
    md_file_path = os.path.join(output_dir, f"{js_basename}_usage.md")
    if os.path.exists(md_file_path):
        with open(md_file_path, "r", encoding="utf-8") as f:
            summary_content = f.read()

        js_file = JSFile.objects.filter(web_app=webapp, name=js_filename).first()
        if js_file:
            js_file.usage_summary = summary_content
            js_file.save()
    else:
        print("md file not found")



if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        generate_usage_summary(sys.argv[1], sys.argv[2])


