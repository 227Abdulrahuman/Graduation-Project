import shodan
import os

key = os.getenv("SHODAN_KEY")

def check():

    if not key:
        return -1

    api = shodan.Shodan(key)

    try:
        api.info()

    except:
        return -1

    return 0