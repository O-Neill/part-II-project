from smartcard.CardRequest import CardRequest
from smartcard.util import toHexString
import os
import sys
sys.path.append(os.path.join(sys.path[0], '../lib/python-rubenesque'))
from rubenesque.curves.sec import secp256r1


def egcd(aa, bb):
    lastremainder, remainder = abs(aa), abs(bb)
    x, lastx, y, lasty = 0, 1, 1, 0
    while remainder:
        lastremainder, (quotient, remainder) = remainder, divmod(lastremainder, remainder)
        x, lastx = lastx - quotient * x, x

        y, lasty = lasty - quotient * y, y
    return lastremainder, lastx, lasty


def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m


# Request any card. Can be more specific using arguments to CardRequest
# contructor.
# Timeout=None means the request waits forever until card is connected.
cardRequest = CardRequest(timeout=None)
cardservice = cardRequest.waitforcard()

connection = cardservice.connection
cardservice.connection.connect()

applet_select = [0x00,  # CLA 00 = ISO7816-4 command
                 0xA4,  # INS A4 = SELECT
                 0x04,  # P1 04 = select by name
                 0x00,  # P2 00 = first or only occurrence
                 0x06,  # Lc 06 = 6 bytes in data field
                 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6]  # Applet ID

data, sw1, sw2 = connection.transmit(applet_select)
print()
print("Selection status: %x %x" % (sw1, sw2))

test_cmac_apdu = [0x80,  # CLA 80 - user defined.
                  0x24,  # INS 23 - Test CMAC.
                  0x00,  # P1  00 - unused
                  0x00,  # P2  00 - unused
                  0x00,  # Total data length
                  0x50]  # Max expected output

data, sw1, sw2 = connection.transmit(test_cmac_apdu)
print(hex(sw1) + ", " + hex(sw2))
#print("Data: %s" % toHexString(data))
print(data)

prime_arr = [0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
             0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
prime = int.from_bytes(prime_arr, byteorder='big')

point_1 = [4,
           209, 3, 31, 104, 36, 73, 169, 115,
           1, 182, 114, 179, 173, 21, 10, 190,
           126, 68, 46, 53, 226, 164, 114, 197,
           178, 170, 158, 92, 189, 185, 220, 167,

           17, 61, 68, 142, 238, 102, 83, 226,
           195, 164, 74, 169, 126, 83, 58, 252,
           3, 217, 47, 52, 108, 139, 233, 109,
           75, 131, 186, 48, 14, 155, 132, 201]

point_2 = [4,
           89, 236, 154, 193, 141, 243, 233, 25,
           68, 167, 178, 189, 144, 142, 190, 72,
           107, 5, 64, 248, 39, 148, 41, 84,
           138, 249, 136, 82, 6, 219, 244, 186,

           249, 28, 4, 149, 176, 246, 23, 102,
           153, 184, 251, 24, 225, 135, 14, 45,
           77, 52, 207, 152, 146, 94, 29, 248,
           206, 15, 141, 85, 193, 53, 117, 44]

y_q = int.from_bytes(point_2[33:65], byteorder='big')
y_p = int.from_bytes(point_1[33:65], byteorder='big')
g, x, y = egcd(y_q, y_p)
print("gcd")
print([i for i in g.to_bytes(length=(g.bit_length() + 7) // 8, byteorder='big')])
print([i for i in x.to_bytes(length=(x.bit_length() + 7) // 8, byteorder='big')])
print()

dy = (y_q - y_p) % prime

x_q = int.from_bytes(point_2[1:33], byteorder='big')
x_p = int.from_bytes(point_1[1:33], byteorder='big')
dx = (x_q - x_p) % prime

dx_inv = modinv(dx, prime)

print("dx_inv:")
print([i for i in dx_inv.to_bytes(length=(dx_inv.bit_length() + 7) // 8, byteorder='big')])
print()

Q = secp256r1.create(int.from_bytes(point_1[1:33], byteorder='big'),
                     int.from_bytes(point_1[33:65], byteorder='big'))
Q2 = secp256r1.create(int.from_bytes(point_2[1:33], byteorder='big'),
                      int.from_bytes(point_2[33:65], byteorder='big'))

Qsum = Q + Q2
x = Qsum.x.to_bytes(length=(Qsum.x.bit_length() + 7) // 8, byteorder='big')
y = Qsum.y.to_bytes(length=(Qsum.x.bit_length() + 7) // 8, byteorder='big')
print()
print([i for i in x])
print([i for i in y])
