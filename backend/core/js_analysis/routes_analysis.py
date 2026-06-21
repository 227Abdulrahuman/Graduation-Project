# Connect to Django
import os, django, subprocess

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backend.websploit.settings")
django.setup()
from backend.core.models import *


def analyze_routes(webapp_url, js_filename):
    # Get Output Directory
    webapp = WebApplication.objects.get(url=webapp_url)
    subdomain = webapp.subdomain.hostname
    clean_webapp_url = webapp_url.replace("://", "_").replace("/", "_").replace(".", "_").replace(":", "_")
    output_dir = os.path.join('/work', 'output', subdomain, clean_webapp_url, 'js')
    os.makedirs(output_dir, exist_ok=True)

    # Prepare Prompt
    prompt = f"""
    Extract routes from  {output_dir}/{js_filename}
    Use jsluice to get the routes.
    ex: `jsluice urls <file.js> > <outputfile>`
    
    Explain the purpose of each route.

    Generate md report at {output_dir}
    md report should STRICTLY FOLLOW THIS NAMING CONVENSION
    nameofjsfile_routes.md example: main.js -> main_routes.md NOT main.js  -> main_routes.js.md
    """

    from backend.core.agents.call_agent import call_agent, check_agent
    ok, msg = check_agent()
    if not ok:
        print(f"[-] Agent check failed: {msg}")
        return
    call_agent(prompt)

    # Store the summary Usage in the database.
    js_basename = os.path.splitext(js_filename)[0]
    md_file_path = os.path.join(output_dir, f"{js_basename}_routes.md")
    if os.path.exists(md_file_path):
        with open(md_file_path, "r", encoding="utf-8") as f:
            summary_content = f.read()

        js_file = JSFile.objects.filter(web_app=webapp, name=js_filename).first()
        if js_file:
            js_file.routes_analysis = summary_content
            js_file.save()
    else:
        print("md file not found")


