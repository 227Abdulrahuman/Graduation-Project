import subprocess


def scrap(domain):
    try:
        cmd = ['subfinder', '-d', domain, '-all', '-nc', '-silent']
        process = subprocess.run(cmd,text=True,capture_output=True)
        output = process.stdout

        subdomains = set()
        for sub in output.splitlines():
            sub = sub.strip()
            subdomains.add(sub)
            subdomains.add(domain)

        return subdomains
    except Exception as e:
        return {-1}