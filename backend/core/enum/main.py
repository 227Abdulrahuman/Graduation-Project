from backend.core.enum.parameter_discovery import parameter_extractor

url = 'http://dvwa.com/'

h = [
    'Cookie: PHPSESSID=3b627brfhp7kblp364ofsnhi15'
    ]

parameter_extractor(url, h)

