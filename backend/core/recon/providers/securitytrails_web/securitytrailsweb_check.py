import os
import re
import requests

def check():
    filepath = "/work/backend/core/recon/resources/securitytrails/cookie.txt"

    if not os.path.exists(filepath):
        return -1

    try:
        with open(filepath, 'r') as file:
            content = file.read()

        ua_match = re.search(r"-H 'user-agent:\s*([^']*)'", content, re.IGNORECASE)

        cookie_match = re.search(r"(?:-b|--cookie) '([^']*)'", content)

        if not cookie_match or not ua_match:
            return -1

        user_agent = ua_match.group(1)
        cookie = cookie_match.group(1)

        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Language": "en-US,en;q=0.9,hi;q=0.8,en-IN;q=0.7",
            "Cookie": cookie,
            "Dnt": "1",
            "Priority": "u=0, i",
            "Sec-Ch-Ua": '"Google Chrome";v="141", "Not?A_Brand";v="8", "Chromium";v="141"',
            "Sec-Ch-Ua-Arch": '"x86"',
            "Sec-Ch-Ua-Bitness": '"64"',
            "Sec-Ch-Ua-Full-Version": '"141.0.7390.108"',
            "Sec-Ch-Ua-Full-Version-List": '"Google Chrome";v="141.0.7390.108", "Not?A_Brand";v="8.0.0.0", "Chromium";v="141.0.7390.108"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Model": '""',
            "Sec-Ch-Ua-Platform": '"Windows"',
            "Sec-Ch-Ua-Platform-Version": '"19.0.0"',
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": user_agent
        }

        test_url = "https://securitytrails.com/list/apex_domain/google.com?page=1"
        response = requests.get(test_url, headers=headers, timeout=10)

        matches = re.findall(r'href="/domain/([^/]+)/dns">', response.text)

        if len(matches) == 0:
            return -1

        return 0

    except Exception:
        return -1