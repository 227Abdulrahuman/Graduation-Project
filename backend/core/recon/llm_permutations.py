import subprocess
import time
from dotenv import load_dotenv
from backend.core.models import *
from backend.core.recon.active_recon import resolve_subdomains

load_dotenv()

def generate_permutations(domain, chunk_size, multiplicity=3):

    live_file = f"/work/output/{domain}/live_subdomains.txt"
    perm_file = f"/work/output/{domain}/unresolved_permutations.txt"
    resolved_file = f"/work/output/{domain}/resolved_permutations.txt"
    diff_file = f"/work/output/{domain}/diff.txt"

    with open(perm_file, 'w') as file:
        pass

    try:
        with open(live_file, 'r') as f:
            subdomains = f.readlines()
    except FileNotFoundError:
        print(f"File not found: {live_file}")
        return

    length = len(subdomains)

    from backend.core.agents.call_agent import call_agent, check_agent
    ok, msg = check_agent()
    if not ok:
        print(f"[-] Agent check failed: {msg}")
        return

    print(f"[*] Generating permutations for {domain}")
    for start in range(0, length, chunk_size):
        print(f"[*] Generating permutations for subdomains from {start} to {start + chunk_size} for {domain}")
        batch = subdomains[start:start + chunk_size]
        batch_content = "".join(batch)

        prompt = f"""
        You are an AI agent that generates subdomains permutations for bug bounty hunting.
        The target domain is {domain}
        I will give you subdomains line by line that belong to this domain and I want you to generate permutations for them.
        Make sure that permutations are subdomains for {domain}
        Your response should only contain permutations.
        Don't place the results inside "```"
        The multiplicity for generation is {multiplicity}
        For example if I gave you 100 subdomains and the multiplicity is 10 I want you to return 1000 potential subdomain.
        Here are the subdomains:
        {batch_content}
        """

        max_retries = 3
        attempt = 0
        success = False

        while not success and attempt < max_retries:
            try:
                result = call_agent(prompt)
                
                if result:
                    with open(perm_file, 'a') as file:
                        file.write(result)

                success = True

            except subprocess.CalledProcessError as e:
                print(f"LLM CLI error: {e.stderr}. Retrying in 5s...")
                time.sleep(5)
                attempt += 1
            except Exception as e:
                print(f"Unexpected error calling LLM CLI: {e}")
                break


    perms = set()
    with open(perm_file, 'r') as fp:
        for line in fp:
            line = line.strip()
            if line.endswith(f".{domain}"):
                perms.add(line)

    with open(perm_file, 'w') as f:
        for line in perms:
            f.write(f"{line}\n")

    print(f"[+] Generated {len(perms)} permutations for {domain}")

    print(f"[*] Resolving permutations for {domain}")
    resolve_subdomains(perm_file, resolved_file)

    with open(resolved_file) as f:
        live_subdomains = set(line.strip() for line in f if line.strip())
        domain_obj = Domain.objects.get(hostname=domain)
        for sub in live_subdomains:
            is_alive = True
            Subdomain.objects.update_or_create(
                domain=domain_obj,
                hostname=sub,
                defaults={"is_alive": is_alive},
            )

    print(f"[+] Resolved {len(live_subdomains)} subdomains from permutations for {domain}")

    proc = subprocess.run(f"cat {resolved_file} | anew {live_file}", shell=True, capture_output=True, text=True)
    new_count = 0
    with open(diff_file, 'w') as df:
        for i in proc.stdout.splitlines():
            new_count += 1
            df.write(f"{i.strip()}\n")
            print(i.strip())

    print(f"[+] Found {new_count} new subdomains from smart bruteforce on {domain}")
