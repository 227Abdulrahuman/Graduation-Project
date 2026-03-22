import requests,re
import os, django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backend.api.settings")
django.setup()
from backend.core.models import *

re_words = re.compile(r'[A-Za-z][A-Za-z0-9_]*')
re_not_junk = re.compile(r'^[A-Za-z0-9_]+$')
re_inputs = re.compile(r'''(?i)<(?:input|textarea)[^>]+?(?:id|name)=["']?([^"'\s>]+)''')
re_empty_vars = re.compile(r'''(?:[;\n]|\bvar|\blet)(\w+)\s*=\s*(?:['"`]{1,2}|true|false|null)''')
re_map_keys = re.compile(r'''['"](\w+?)['"]\s*:\s*['"`]''')

def is_not_junk(param):

    if param.startswith('_'):
        return False

    if param.endswith('_'):
        return False

    if param.lower().startswith('utm_'):
        return False

    return (re_not_junk.match(param) is not None)

def extract_js(response):
    """
    extracts javascript from a given string
    """
    scripts = []
    for part in re.split('(?i)<script[> ]', response):
        actual_parts = re.split('(?i)</script>', part, maxsplit=2)
        if len(actual_parts) > 1:
            scripts.append(actual_parts[0])
    return scripts

def heuristic(raw_response):
    """
    Takes a Response object and returns a list of parameters.
    """
    potential_params = []

    headers, response = raw_response.headers, raw_response.text
    # Parse Inputs
    input_names = re_inputs.findall(response)
    potential_params += input_names

    # Parse Scripts
    for script in extract_js(response):
        empty_vars = re_empty_vars.findall(script)
        potential_params += empty_vars

        map_keys = re_map_keys.findall(script)
        potential_params += map_keys

    if len(potential_params) == 0:
        return []

    found = set()
    for word in potential_params:
        if is_not_junk(word) and (word not in found):
            found.add(word)

    return list(found)


def parse_headers(header_list):
    """
    Takes a header list and returns a dict of headers to pass to request.
    """
    headers_dict = {}

    for header in header_list:
        if ":" in header:
            key, value = header.split(":", 1)

            headers_dict[key.strip()] = value.strip()

    return headers_dict

