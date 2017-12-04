# TODO: Issue card with CVC.
import asn1
from smartcard.CardRequest import CardRequest
import hashlib

# TODO: Could incorporate upload script into this program.
# TODO: Consider possibility of attacker messing with card's stored keys.

# NOTE: Overview - get card to generate keys, send public.
# This app will then send CVC containing public key. No handy way to do it on
# Java Card and would probably be quicker on host anyway.


# Input key as bytearray. Encodes according to Opacity CVC spec.
def encode_key(key):
    # First suggested Object ID. Not sure if best.
    # Corresponds to 1.3.132.0.33
    keyencoder = asn1.Encoder()
    keyencoder.start()
    keyencoder.write('1.2.840.10045.3.1.7', 0x06)
    formattedkey = bytearray([0x04])
    formattedkey.extend(key)
    keyencoder.write(bytes(formattedkey), 0x86)
    return keyencoder.output()


def select(connection):

    applet_select = [0x00,  # CLA 00 = ISO7816-4 command
                     0xA4,  # INS A4 = SELECT
                     0x04,  # P1 04 = select by name
                     0x00,  # P2 00 = first or only occurrence
                     0x06,  # Lc 05 = 8 bytes in data field
                     0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6]  # Applet ID

    data, sw1, sw2 = connection.transmit(applet_select)
    # TODO: expect sw1,sw2 is success. If not, throw exception.


def generate_card_keys(connection, issuer_id, guid):
    # Send issuer ID, guID so card can calculate signature.
    keygen_request = [0x80,  # CLA 80 - user defined.
                      0x21]  # INS 21 - Generate key request.
    keygen_request.append(len(issuer_id))  # P1 - length of issuer ID
    keygen_request.append(0x00)  # P2  00 - unused
    keygen_request.append(len(issuer_id) + len(guid))  # Lc - total data length
    keygen_request.extend(issuer_id)
    keygen_request.extend(guid)
    keygen_request.append(0x41)  # Expect 65B Pubkey (0x41 in Hex).
    data, sw1, sw2 = connection.transmit(keygen_request)
    pubkey = data[0:65]
    signature = data[65:]
    print("Get data:\n" + str(pubkey))
    print(hex(sw1) + ", " + hex(sw2))
    return pubkey, signature


def format_cvc(connection, signature):
    # TODO: use proper values (not just test ones)
    # 6B Issuer ID, 2B Issuer Key ID (for issued CVC)
    issuerID = bytes([0, 0, 0, 0, 0, 0, 0, 1])

    # Globally Unique ID - Application specific, identifies card or cardholder.
    # Could be generated from a counter.
    guID = bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 1])

    pubkey, signature = generate_card_keys(connection, issuerID, guID)

    encoder = asn1.Encoder()
    encoder.start()

    encoder.write(bytes([0x80]), 0x5F29)

    encoder.write(issuerID, 0x42)

    encoder.write(guID, 0x5F20)
    encoded_key = encode_key(pubkey)

    encoder.write(encoded_key, 0x7F49)

    # TODO: Format properly, copying in the signature value (which isn't fully
    # encoded in DER form).
    encoder.write(bytes(signature), 0x5F37)

    # role ID: 0x00 for card application key CVC
    encoder.write(bytes([0x00]), 0x5F4C)

    print("cvc: " + str(encoder.output()))

    return encoder.output()


def send_cvc(connection, cvc):
    set_cvc_apdu = [0x80,  # CLA 80 - user defined.
                    0x22,  # INS 21 - Generate key request.
                    0x00,  # P1  00 - unused
                    0x00,  # P2  00 - unused
                    len(cvc)]  # Total data length
    set_cvc_apdu.extend(cvc)
    print("cvc apdu: " + str(set_cvc_apdu))

    data, sw1, sw2 = connection.transmit(set_cvc_apdu)
    print("Upload:\n" + str(data))
    print(hex(sw1) + ", " + hex(sw2))


cardRequest = CardRequest(timeout=None)
cardservice = cardRequest.waitforcard()

connection = cardservice.connection
cardservice.connection.connect()

# Select the OPACITY applet
select(connection)

# Format CVC from information obtained from the card.
cvc = format_cvc(connection)

# Upload the CVC onto the card.
send_cvc(connection, cvc)
