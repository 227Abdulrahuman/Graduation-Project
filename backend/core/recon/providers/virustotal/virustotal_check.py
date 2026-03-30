import requests,os

API_KEY = os.getenv("VIRUSTOTAL_KEY")
url = f"https://www.virustotal.com/api/v3/users/{API_KEY}"

headers = {
    "accept": "application/json",
    "x-apikey": API_KEY
}

def check():

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return 0
    else:
        return -1