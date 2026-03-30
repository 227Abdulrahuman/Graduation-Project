import subprocess

#https://securitytrails.com/list/apex_domain/krazeplanet.com?page=1

def scrap(domain):
    try:
        cmd = ["haktrailsfree", "-d", domain, "-c", "/work/backend/core/recon/resources/securitytrails/cookie.txt", "--silent"]
        proc = subprocess.run(cmd,text=True,capture_output=True)

        subdomains = set()
        for line in proc.stdout.splitlines():
            line = line.strip()
            subdomains.add(line)

        return subdomains
    except Exception as e:
        return {-1}