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
            cvc = int(binding.find('cvc').text)
            cvc = cvc.to_bytes(length=(cvc.bit_length() + 7) // 8, byteorder='big')
            secret = int(binding.find('secret').text)
            self.bindings[int(binding.find('id').text)] = (secret, cvc)

    def contains(self, card_id):
        return card_id in self.bindings

    def getCardInfo(self, card_id):
        return self.bindings[card_id]


    def addRecord(self, card_id, secret, cvc):
        if (self.contains(card_id)):
            # TODO: Instead, update existing entry
            return
        self.bindings[card_id] = (secret, cvc)
        newentry = ET.SubElement(self.tree.getroot(), 'binding')
        ET.SubElement(newentry, 'id').text = str(card_id)
        ET.SubElement(newentry, 'secret').text = str(int.from_bytes(secret, byteorder='big'))
        #ET.SubElement(newentry, 'cvc').text = str(int.from_bytes(cvc, byteorder='big'))
        print(cvc)
        ET.SubElement(newentry, 'cvc').text = str(int.from_bytes(cvc, byteorder='big'))
        self.tree.write(self.filename)
