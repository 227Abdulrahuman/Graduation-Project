import django, subprocess, os, shlex, json
from urllib.parse import urlparse, parse_qsl, urlsplit

# Django Setup
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backend.api.settings")
django.setup()
from backend.core.models import *

def crawl(url, auth_headers=None, logout=None):
    """
    Crawl a target webapp, and saves endpoints and parameters to the database.
    """


    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
    except:
        print(f"[-] Not a valid url {url}")
        return

    out_dir = f'/work/backend/core/enum/output/{hostname}'
    out_file = f'{out_dir}/katana.json'
    os.makedirs(out_dir, exist_ok=True)

    cmd = ["katana", "-u", url, "-j", "-o", out_file]

    if auth_headers:
        for header in auth_headers:
            cmd.extend(["-H", header])

    if logout:
        cmd.extend(["-cos", logout])

    print(f"[*] Executing: {shlex.join(cmd)}")

    subprocess.run(cmd, capture_output=True, text=True)

    all_urls = set()
    with open(out_file, 'r') as file:

        for line in file:
            data = json.loads(line)

            url = data["request"].get("endpoint")

            try:
                urlparse(url)
                all_urls.add(url)
            except:
                pass

    #Decuttle the urls.
    urls_file = f"{out_dir}/urls.txt"
    with open(urls_file, 'w') as file:
        for i in all_urls:
            file.write(f"{i}\n")

    urls_file_decutled = f"{out_dir}/urls.decutled.txt"
    cmd = ['urless', '-i', urls_file, '-o', urls_file_decutled]
    subprocess.run(cmd, capture_output=True, text=True)

    sub = Subdomain.objects.get(hostname=hostname)
    params = set()
    endpoints = set()

    with open(urls_file_decutled, 'r') as file:
        for line in file:
            line = line.strip()
            parsed_url = urlparse(line)

            #Get endpoints.
            endpoints.add(parsed_url.path)

            #Get parameters. (key,value)
            params_list = parse_qsl(parsed_url.query)
            for i in params_list:
                params.add(i)


    params_output = f"{out_dir}/params.txt"
    with open(params_output, 'w') as file:
        for i in params:
            file.write(f"{i[0]}={i[1]}\n")

    for i in params:
        Parameter.objects.update_or_create(
            subdomain=sub,
            key=i[0],
            defaults={
                "value":i[1],
            }
        )


    endpoints_output = f"{out_dir}/endpoints.txt"
    with open(endpoints_output, 'w') as file:
        for i in endpoints:
            if i.removeprefix('/'):
                file.write(f"{i.removeprefix('/')}\n")

    #Prepare ffuf url.
    split_url = urlsplit(url)
    ffuf_url = f"{split_url.scheme}://{split_url.netloc}"
    ffuf_output = f"{out_dir}/ffuf.json"

    #Run ffuf.
    cmd = ['ffuf', '-u', f"{ffuf_url}/FUZZ",
           '-w', endpoints_output,
           '-ac',
           '-o', ffuf_output
           ]
    if auth_headers:
        for header in auth_headers:
            cmd.extend(["-H", header])

    print(f"[*] Executing: {shlex.join(cmd)}")
    subprocess.run(cmd, capture_output=True, text=True)

    #parse json.
    with open(ffuf_output,'r') as file:
        data = json.load(file)


    for i in data["results"]:
        l = i.get("url")
        sc = i.get("status")
        ct = i.get("content-type")
        rl = i.get("redirectlocation")

        URL.objects.update_or_create(
            subdomain=sub,
            endpoint=l,

            defaults={
                "status_code": sc,
                "content_type": ct,
                "location": rl,
            }
        )







if __name__ == "__main__":
    crawl("http://dvwa.com/index.php", ["Cookie: PHPSESSID=ifugcco9sf7kg9qnsourfobu70"], "logout.php")