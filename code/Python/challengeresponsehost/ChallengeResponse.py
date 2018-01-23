from smartcard.CardType import ATRCardType
from smartcard.CardRequest import CardRequest
from smartcard.util import toHexString, toBytes

# Request any card. Can be more specific using arguments to CardRequest
# contructor.
# Timeout=None means the request waits forever until card is connected.
cardRequest = CardRequest(timeout=None)
cardservice = cardRequest.waitforcard()

connection = cardservice.connection
cardservice.connection.connect()
print()
print("Reader: " + connection.getReader())

applet_select = [0x00,  # CLA 00 = ISO7816-4 command
                 0xA4,  # INS A4 = SELECT
                 0x04,  # P1 04 = select by name
                 0x00,  # P2 00 = first or only occurrence
                 0x06,  # Lc 05 = 8 bytes in data field
                 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6]  # Applet ID

data, sw1, sw2 = connection.transmit(applet_select)
print("Applet select status: %x %x" % (sw1, sw2))
print("Data: %s" % toHexString(data))

hellostring = "Hello World"
arr = [ord(elem) for elem in hellostring]

send_apdu = [0x80,  # CLA 80 = user defined
             0x30,  # INS 30 = user defined
             0x00,  # P1 00
             0x00]  # P2 00
send_apdu.append(len(arr))  # Length of hello string
send_apdu.extend(arr)  # Hex-encoded Hello string
send_apdu.append(2)  # 2 bytes for debugging purposes.

print("sending: %s" % str(send_apdu))
data, sw1, sw2 = connection.transmit(send_apdu)
print("Send status: %x %X" % (sw1, sw2))
print("Data: %s" % toHexString(data))

read_apdu = [0x80,  # CLA 80 = user defined
             0x31,  # INS 30 = user defined
             0x00,  # P1 00
             0x00,  # P2 00
             len(arr)]  # Enough for applet to write back earlier message.

data, sw1, sw2 = connection.transmit(read_apdu)
print("Send status: %x %X" % (sw1, sw2))
ret_hex = data
print("Data: %s" % ret_hex)
ret_string = "".join([chr(elem) for elem in ret_hex])
print("Returned: %s" % ret_string)
