import os
import time
from itertools import cycle
from dotenv import load_dotenv

from google import genai
from google.genai import types, errors

load_dotenv()

def get_client_cycle():
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

client_pool = get_client_cycle()

def generate_permutations(domain):
    """
    Takes subdomains from passive.txt and generates permutations in permutations.txt
    """
    passive_file = f"/work/backend/core/recon/output/{domain}/passive.txt"
    out_file = f"/work/backend/core/recon/output/{domain}/permutations.txt"

    with open(out_file, 'w') as file:
        pass

    chunk_size = 3000

    try:
        with open(passive_file, 'r') as f:
            subdomains = f.readlines()
    except FileNotFoundError:
        print(f"File not found: {passive_file}")
        return

    length = len(subdomains)

    current_client = next(client_pool)

    for start in range(0, length, chunk_size):
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
                    with open(out_file, 'a') as file:
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