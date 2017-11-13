from smartcard.CardType import ATRCardType
from smartcard.CardRequest import CardRequest
from smartcard.util import toHexString, toBytes
from time import sleep

print "Acquiring card"

# Request any card. Can be more specific using arguments to CardRequest
# contructor.
# Timeout=None means the request waits forever until card is connected.
cardRequest = CardRequest(timeout=None)
cardservice = cardRequest.waitforcard()

connection = cardservice.connection
cardservice.connection.connect()
print "ATR: %s" % toHexString(connection.getATR())
print "Reader: " + connection.getReader()

ISD_select = [0x00,  # CLA 00 = ISO7816-4 command
              0xA4,  # INS A4 = SELECT
              0x04,  # P1 04  = select by name
              0x00,  # P2 00  = First or only occurrence
              0x08,  # Lc 08  = 8 bytes in data field
              0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00]  # ISD

data, sw1, sw2 = connection.transmit(ISD_select)
print "Selection status: %x %x" % (sw1, sw2)

applet_select = [0x00,  # CLA 00 = ISO7816-4 command
                 0xA4,  # INS A4 = SELECT
                 0x04,  # P1 04 = select by name
                 0x00,  # P2 00 = first or only occurrence
                 0x05,  # Lc 05 = 8 bytes in data field
                 0xD1, 0xD2, 0xD3, 0xD4, 0xD5]  # Applet ID

data, sw1, sw2 = connection.transmit(applet_select)
print "Applet select status: %x %x" % (sw1, sw2)
print "Data: %s" % toHexString(data)

test_apdu = [0x80,  # CLA 80 = user defined
             0x30,  # INS 30 = user defined
             0x00,  # P1 00
             0x00,  # P2 00
             0x03]  # Le = 3, expected 3 bytes returned.

data, sw1, sw2 = connection.transmit(test_apdu)
print "Test status: %x %X" % (sw1, sw2)
print "Data: %s" % toHexString(data)
