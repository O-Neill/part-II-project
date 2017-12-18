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


# Format of sig is (r,s) concatenated directly, 32B each. Encode using BER.
def encode_sig(sig):
    sigencoder = asn1.Encoder()
    sigencoder.start()
    # Start overall sequence for containing the signature data.
    sigencoder.enter(0x10)
    # Start algorithm identifier sequence
    sigencoder.enter(0x10)
    sigencoder.write('1.2.840.10045.4.3.2', 0x06)
    sigencoder.leave()
    sigencoder.enter(0x10)
    # NOTE: Assume r and s stored in the same number of bytes.
    intlen = int(len(sig) / 2)
    print("number: " + str(int.from_bytes(bytes(sig[intlen:]), byteorder='big')))
    sigencoder.write(int.from_bytes(bytes(sig[:intlen]), byteorder='big'), 0x02)  # Write 'r' value.
    sigencoder.write(int.from_bytes(bytes(sig[intlen:]), byteorder='big'), 0x02)  # Write 's' value.
    sigencoder.leave()
    sigencoder.leave()
    return sigencoder.output()


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
    keygen_request.append(0x81)  # Expect 65B Pubkey and 64B signature.
    data, sw1, sw2 = connection.transmit(keygen_request)
    pubkey = data[0:65]
    signature = data[65:]
    print(hex(sw1) + ", " + hex(sw2))
    return pubkey, signature


def format_cvc(connection):
    # TODO: use proper values (not just test ones)
    # 6B Issuer ID, 2B Issuer Key ID (for issued CVC)
    issuerID = bytes([0, 0, 0, 0, 0, 0, 0, 1])

    # Globally Unique ID - Application specific, identifies card or cardholder.
    # Could be generated from a counter.
    guID = bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 1])

    pubkey, signature = generate_card_keys(connection, issuerID, guID)
    print("Signature: \n" + str(signature) + ", length " + str(len(signature)))

    encoder = asn1.Encoder()
    encoder.start()

    encoder.write(bytes([0x80]), 0x5F29)

    encoder.write(issuerID, 0x42)

    encoder.write(guID, 0x5F20)
    encoded_key = encode_key(pubkey)

    encoder.write(encoded_key, 0x7F49)

    encoder.write(encode_sig(signature), 0x5F37)

    # role ID: 0x00 for card application key CVC
    encoder.write(bytes([0x00]), 0x5F4C)

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
    print(hex(sw1) + ", " + hex(sw2))


# SHA-256, input val as byte array, generate 256-bit hash code as byte array.
def hashfun(val):
    hash_obj = hashlib.sha256()
    hash_obj.update(val)
    return hash_obj.digest()


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

card_id = hashfun(cvc)[:8]
id_file = open("trusted_card_id.txt")


# TODO: Calculate ID from CVC, and save it as an approved card.
