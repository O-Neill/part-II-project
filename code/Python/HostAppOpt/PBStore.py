import os.path
import xml.etree.ElementTree as ET


# card_id inputs should be of type int, secret of type bytes.
class Store:
    # Contains name of XML file to initialise from
    def __init__(self, filename):
        self.filename = filename
        self.bindings = {}
        if not os.path.exists(filename):
            self.tree = ET.ElementTree(element=ET.Element('bindings'))
            return

        self.tree = ET.parse(filename)
        root = self.tree.getroot()
        for binding in root.findall('binding'):
            print(binding.find('id').text)
            self.bindings[int(binding.find('id').text)] = binding.find('secret').text

    def exists(self, card_id):
        return card_id in self.bindings

    def getSecret(self, card_id):
        return int(self.bindings[card_id])

    def addRecord(self, card_id, secret):
        print(self.bindings)
        print(card_id)
        print()
        if (self.exists(card_id)):
            return
        self.bindings[card_id] = secret
        newentry = ET.SubElement(self.tree.getroot(), 'binding')
        ET.SubElement(newentry, 'id').text = str(card_id)
        ET.SubElement(newentry, 'secret').text = str(int.from_bytes(secret, byteorder='big'))
        self.tree.write(self.filename)
