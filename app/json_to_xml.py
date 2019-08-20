import xml.etree.ElementTree as ET
import json
import sys
import argparse
import Function as F


def Json_to_xml(_json, _xml, _id="mxb"):
    tree = ET.parse(str(_xml))
    root = tree.getroot()

    with open(_json) as json_file:
        data=json.load(json_file)
    json_file.close()

    for k, v in data.items():
        if v != -2:
            element=ET.SubElement(
                root.find('nvm'), 'param', F.DictForParamTAG(k, v))

    root.set('productID', str(_id))
    tree.write('max4.xml')
