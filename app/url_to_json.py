import requests
import re
import json
import sys
import argparse

def Url_to_json(url,reg):

    responce = requests.get(url)
    dictionary = {}
    match = re.finditer(reg, responce.text)

    for matchNum, match in enumerate(match, start=1):
        key = match.group()
        dictionary[key] = -2
        
    fjson = json.dumps(dictionary, indent=4)
    f = open("app/dict.json", "w")
    f.write(fjson)
    f.close()
    print("ok")

    




