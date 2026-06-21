# Connect to Django
import os, django, subprocess

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backend.websploit.settings")
django.setup()
from backend.core.models import *


def review_code(webapp_url, js_filename):
    # Get Output Directory
    webapp = WebApplication.objects.get(url=webapp_url)
    subdomain = webapp.subdomain.hostname
    clean_webapp_url = webapp_url.replace("://", "_").replace("/", "_").replace(".", "_").replace(":", "_")
    output_dir = os.path.join('/work', 'output', subdomain, clean_webapp_url, 'js')
    os.makedirs(output_dir, exist_ok=True)
    
    # Prepare Prompt
    prompt = f"""
    Find Client Side Vulnerabilities in {output_dir}/{js_filename}
    You can use jsluice to get the AST of the file
    ex: `jsluice tree <file.js> > <outputfile>`
    You can check for leaked cred using 
    ex: `jsluice secrets <file.js> > <outputfile>`
    
    Focus on client side bugs that have a clear source and a sink, that are reproduceable.
    Focus on bugs that can be exploited externally not by proxing victim traffic.
    NOT BY CHANGING THE HTTP RESPONSE 


    Generate md report at {output_dir}
    md report should STRICTLY FOLLOW THIS NAMING CONVENSION
    nameofjsfile_code_review.md example: main.js -> main_code_review.md NOT main.js  -> main_code_review.js.md
    """

    from backend.core.agents.call_agent import call_agent, check_agent
    ok, msg = check_agent()
    if not ok:
        print(f"[-] Agent check failed: {msg}")
        return
    call_agent(prompt)

    # Store the summary Usage in the database.
    js_basename = os.path.splitext(js_filename)[0]
    md_file_path = os.path.join(output_dir, f"{js_basename}_code_review.md")
    if os.path.exists(md_file_path):
        with open(md_file_path, "r", encoding="utf-8") as f:
            summary_content = f.read()

        js_file = JSFile.objects.filter(web_app=webapp, name=js_filename).first()
        if js_file:
            js_file.code_review = summary_content
            js_file.save()
    else:
        print("md file not found")


