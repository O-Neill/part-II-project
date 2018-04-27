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
            self.bindings[int(binding.find('id').text)] = (binding.find('secret').text, binding.find('cvc').text)

    def contains(self, card_id):
        return card_id in self.bindings

    def getCardInfo(self, card_id):
        print("Getting PB value")
        print(self.bindings[card_id])
        print(int.from_bytes(self.bindings[card_id][0], byteorder='big'))
        print(self.bindings[card_id][1])
        return int.from_bytes(self.bindings[card_id][0], byteorder='big'), self.bindings[card_id][1]


    def addRecord(self, card_id, secret, cvc):
        print(card_id)
        print()
        if (self.contains(card_id)):
            # TODO: Instead, update existing entry
            return
        self.bindings[card_id] = (secret, cvc)
        newentry = ET.SubElement(self.tree.getroot(), 'binding')
        ET.SubElement(newentry, 'id').text = str(card_id)
        ET.SubElement(newentry, 'secret').text = str(int.from_bytes(secret, byteorder='big'))
        ET.SubElement(newentry, 'cvc').text = str(int.from_bytes(cvc, byteorder='big'))
        self.tree.write(self.filename)
