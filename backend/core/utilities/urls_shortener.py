import re
from urllib.parse import urlparse


def shorten_urls(urls, keep_slash= False, keep_human_written= False, keep_yyyymm = False):
    """
    Takes a set of URLs and returns a set of shortened URLs.
    """

    filter_keywords = "blog,article,news,job,item,store,book"
    re_filter_keywords = re.compile(filter_keywords.replace(",", "|"), re.IGNORECASE)

    regex_int = r"^\d+$"
    regex_guid = r"^[({]?[a-fA-F0-9]{8}[-]?([a-fA-F0-9]{4}[-]?){3}[a-fA-F0-9]{12}[})]?$"
    regex_yyyymm = r"\/[1|2][0|1|9]\d{2}/[0|1]\d{1}\/"

    re_int_part = re.compile(regex_int)
    re_guid_part = re.compile(regex_guid)
    re_yyyymm_part = re.compile(regex_yyyymm)

    urlmap = {}
    patterns_int = {}
    patterns_guid = {}
    patterns_seen = set()

    for line in urls:
        line = line.strip()
        if not line:
            continue

        if not keep_slash:
            line = line.rstrip("/")

        line = line.split("?")[0].split("#")[0]

        parsed = urlparse(line)
        host = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme else parsed.netloc

        path = parsed.path

        if host not in urlmap:
            urlmap[host] = set()

        if path != "":
            unwanted = False

            if not keep_human_written:
                for part in path.split("/"):
                    if part.count("-") > 3 and not re_guid_part.search(part):
                        unwanted = True

            if not keep_yyyymm and re_yyyymm_part.search(path):
                unwanted = True

            if unwanted or re_filter_keywords.search(path):
                continue

            matched = False
            for pattern in patterns_seen:
                if re.search(pattern, re.escape(path)) is not None:
                    matched = True
                    break
            if matched:
                continue

        if "++" in path:
            pattern = path
        else:
            new_parts = []
            is_guid, is_int = False, False
            for part in path.split("/"):
                if part == "":
                    new_parts.append(part)
                elif re_guid_part.search(part):
                    is_guid = True
                    new_parts.append(regex_guid)
                elif re_int_part.match(part):
                    is_int = True
                    new_parts.append(regex_int)
                else:
                    new_parts.append(part)

            pattern = "/".join(new_parts)

            if is_guid and pattern not in patterns_guid:
                patterns_guid[pattern] = path
            elif is_int and pattern not in patterns_int:
                patterns_int[pattern] = path

            patterns_seen.add(pattern)

        urlmap[host].add(pattern)

    shortened_set = set()

    for host, paths in urlmap.items():
        for path_pattern in paths:

            final_path = path_pattern
            if regex_guid in final_path and final_path in patterns_guid:
                final_path = patterns_guid[final_path]
            elif regex_int in final_path and final_path in patterns_int:
                final_path = patterns_int[final_path]

            shortened_set.add(f"{host}{final_path}")

    return shortened_set