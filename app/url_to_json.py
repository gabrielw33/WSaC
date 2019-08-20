import requests
import re
import json
import sys
import argparse


parser = argparse.ArgumentParser(description='url')
parser.add_argument('url', type=str, help="url")
parser.add_argument('reg', type=str, help="the regular expression \
        must be enclosed in brackets and quotation marks")
args = parser.parse_args()


if len(sys.argv) < 2:
    print("Error : no parameter")
else:
    url = args.url

responce = requests.get(url)
dictionary = {}
reg = args.reg
match = re.finditer(reg, responce.text)

for matchNum, match in enumerate(match, start=1):
    key = match.group()
    dictionary[key] = -2

json = json.dumps(dictionary, indent=4)
f = open("dict2.json", "w")
f.write(json)
f.close()
