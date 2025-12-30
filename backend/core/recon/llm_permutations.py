from backend.core.utilities.load_subdomains import load_subdomains
from google import genai
from google.genai import types

client = genai.Client()

def generate_permutations(domain):
    """
    Takes a domain and generates permutations and saves them to permutations.txt
    """
    #Load the subdomains from the database.
    passive_file = f"/work/backend/core/recon/output/{domain}/passive.txt"
    out_file = f"/work/backend/core/recon/output/{domain}/permutations.txt"
    load_subdomains(domain, passive_file)

    #Clear the permutations file.
    with open(out_file, 'w') as file:
        pass


    chunk_size = 3000

    with open(passive_file, 'r') as f:
        subdomains = f.readlines()
        length = len(subdomains)

    for start in range(0, length, chunk_size):
        batch = subdomains[start:start+chunk_size]

        prompt = """
        You are an AI agent that does subdomains permutations for bug bounty hunting.
        I will give you subdomains line by line and I want you to generate permutations for them.
        Your response should only contain permutations.
        Don't place the results inside "```"
        Here are the subdomains:\n"""

        for subdomain in batch:
            prompt += subdomain

        response = client.models.generate_content(
            model="gemini-2.5-flash", contents=prompt,
            config=types.GenerateContentConfig(thinking_config=types.ThinkingConfig(thinking_budget=0)),
        )

        with open(out_file, 'a') as file:
            for i in response.text:
                file.write(i)


domain = "panasonic.com"

generate_permutations(domain)