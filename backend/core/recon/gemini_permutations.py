import os, subprocess
import time
from itertools import cycle
from dotenv import load_dotenv
from backend.core.models import *
from backend.core.recon.active_recon import resolve_subdomains
from google import genai
from google.genai import types, errors

load_dotenv()

def get_key():
    """
    Loads API keys from env and returns a cycling iterator of genai Clients.
    """
    keys_str = os.getenv("GOOGLE_API_KEYS", "")
    keys = [k.strip() for k in keys_str.split(",") if k.strip()]

    if not keys:
        i = 1
        while True:
            k = os.getenv(f"GOOGLE_API_KEY_{i}")
            if not k:
                break
            keys.append(k)
            i += 1

    if not keys:
        single_key = os.getenv("GOOGLE_API_KEY")
        if single_key:
            keys = [single_key]
        else:
            raise ValueError("No GOOGLE_API_KEYS found in environment variables.")

    print(f"Loaded {len(keys)} API keys for rotation.")

    client_list = [genai.Client(api_key=key) for key in keys]
    return cycle(client_list)

client_pool = get_key()

def generate_permutations(domain, chunk_size):

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

    current_client = next(client_pool)

    print(f"[*] Generating permutations for {domain}")
    for start in range(0, length, chunk_size):
        print(f"[*] Generating permutations for subdomains from {start} to {start + chunk_size} for {domain}")
        batch = subdomains[start:start + chunk_size]
        batch_content = "".join(batch)

        prompt = f"""
        You are an AI agent that does subdomains permutations for bug bounty hunting.
        The target domain is {domain}
        I will give you subdomains line by line that belong to this domain and I want you to generate permutations for them.
        Make sure that permutations are subdomains for {domain}
        Your response should only contain permutations.
        Don't place the results inside "```"
        Here are the subdomains:
        {batch_content}
        """

        max_retries = 10
        attempt = 0
        success = False

        while not success and attempt < max_retries:
            try:
                response = current_client.models.generate_content(
                    model="gemini-2.5-flash",
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        thinking_config=types.ThinkingConfig(thinking_budget=0)
                    ),
                )

                if response.text:
                    with open(perm_file, 'a') as file:
                        file.write(response.text)

                success = True

            except errors.ClientError as e:
                if e.code == 429:
                    print(f"Rate limit hit (429). Rotating API key...")
                    current_client = next(client_pool)
                    attempt += 1
                    time.sleep(1)
                else:
                    print(f"LLM Client Error (Non-retryable): {e.code} - {e.message}")
                    break

            except errors.ServerError as e:
                print(f"LLM Server Error: {e.code}. Retrying in 5s...")
                time.sleep(5)
                attempt += 1

            except Exception as e:
                print(f"LLM unexpected error occurred: {e}")
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