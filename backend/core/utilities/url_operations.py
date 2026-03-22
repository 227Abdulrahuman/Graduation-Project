from urllib.parse import urlparse

def count_path_parts(url):
    path = urlparse(url).path
    parts = [p for p in path.strip("/").split("/") if p]

    return len(parts)