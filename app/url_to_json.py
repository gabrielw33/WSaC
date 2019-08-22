import re
import sys
import json
import argparse
import requests


def Url_to_json(url, reg):
    responce = requests.get(url)
    dictionary = {}
    match = re.finditer(reg, responce.text)
    for matchNum, match in enumerate(match, start=1):
        key = match.group()
        dictionary[key] = -2
    json_from_dict = json.dumps(dictionary, indent=4)
    json_file = open("dict.json", "w+")
    json_file.write(json_from_dict)
    json_file.close()
    print("ok")
    return json_file.name
