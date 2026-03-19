from urllib.parse import urlparse


def declutter_urls(cluttered_urls, threshold=5):
    """
    Takes a list of cluttered URLs and returns de-cluttered list.
    """
    unique_urls = list(dict.fromkeys(cluttered_urls))
    groups = {}

    for url in unique_urls:
        parsed = urlparse(url)
        path_parts = parsed.path.split('/')

        sig_parts = []
        for part in path_parts:
            if part.isnumeric() or '-' in part:
                sig_parts.append('<VAR>')
            else:
                sig_parts.append(part)

        sig_path = '/'.join(sig_parts)

        signature = f"{parsed.scheme}://{parsed.netloc}{sig_path}"

        if signature not in groups:
            groups[signature] = []
        groups[signature].append(url)

    decluttered_urls = []
    for group in groups.values():
        if len(group) >= threshold:
            decluttered_urls.append(group[0])
        else:
            decluttered_urls.extend(group)

    return decluttered_urls