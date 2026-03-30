import os
import shodan

SHODAN_KEY = os.getenv("SHODAN_KEY")


def scrap(domain):
    subdomains = set()

    api = shodan.Shodan(SHODAN_KEY)
    page_num = 1

    while True:
        try:
            response_data = api.dns.domain_info(domain, page=page_num)

            prefix_subs = response_data.get("subdomains", [])
            for prefix in prefix_subs:
                subdomains.add(f"{prefix}.{domain}")

            if not response_data.get("more"):
                break

            page_num += 1

        except shodan.APIError:

            break

    return subdomains