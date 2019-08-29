import json
import sys
import argparse
import Function as F
import xml.etree.ElementTree as ET


def Json_to_xml(_json_name, _xml_name, _xml_file, _id="mxb"):
    if _id == '':
        _id = "mxb"
    tree = ET.parse(_xml_file)
    root = tree.getroot()

    with open(_json_name) as json_file:
        data = json.load(json_file)
    json_file.close()

    for k, v in data.items():
        if v != -2:
            element = ET.SubElement(
                root.find('nvm'), 'param', F.DictForParamTAG(k, v))

    root.set('productID', str(_id))
    tree.write(_xml_name)