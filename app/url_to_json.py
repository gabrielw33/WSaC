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
        
    json = json.dumps(dictionary, indent=4)
    f = open("dict2.json", "w")
    f.write(json)
    f.close()


    




