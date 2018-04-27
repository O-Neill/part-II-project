import asn1
from smartcard.CardRequest import CardRequest
import hashlib
import os

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, \
                                                         NoEncryption, \
                                                         PrivateFormat, \
                                                         PublicFormat, \
                                                         load_der_private_key

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
    formattedkey = bytearray()
    formattedkey.extend(key)
    keyencoder.write(bytes(formattedkey), 0x86)
    return keyencoder.output()


# Format of sig is (r,s) concatenated directly, 32B each. Encode using BER.
def encode_sig(sig):
    # NOTE: UNUSED
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

    # Write r and s values
    sigencoder.write(int.from_bytes(bytes(sig[:intlen]), byteorder='big'), 0x02)
    sigencoder.write(int.from_bytes(bytes(sig[intlen:]), byteorder='big'), 0x02)
    sigencoder.leave()
    sigencoder.leave()
    return sigencoder.output()


def select(connection):

    applet_select = [0x00,  # CLA 00 = ISO7816-4 command
                     0xA4,  # INS A4 = SELECT
                     0x04,  # P1 04 = select by name
                     0x00,  # P2 00 = first or only occurrence
                     0x06,  # Lc 06 = 6 bytes in data field
                     0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6]  # Applet ID

    data, sw1, sw2 = connection.transmit(applet_select)
    print("select")
    print(hex(sw1) + ", " + hex(sw2))
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
    keygen_request.append(65)  # Expect 65B Pubkey.
    pubkey, sw1, sw2 = connection.transmit(keygen_request)
    print('Gen keys')
    print(hex(sw1) + ", " + hex(sw2))
    return pubkey


def format_cvc(connection, private_key):
    # TODO: use proper values (not just test ones)
    # 6B Issuer ID, 2B Issuer Key ID (for issued CVC)
    issuerID = bytes([0, 0, 0, 0, 0, 0, 0, 1])

    # Globally Unique ID - Application specific, identifies card or cardholder.
    # Could be generated from a counter.
    guID = bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])

    roleID = bytes([0x00])

    pubkey = generate_card_keys(connection, issuerID, guID)


    encoder = asn1.Encoder()
    encoder.start()

    encoder.write(bytes([0x80]), 0x5F29)

    encoder.write(issuerID, 0x42)

    encoder.write(guID, 0x5F20)

    encoded_key = encode_key(pubkey)
    encoder.write(encoded_key, 0x7F49)

    data = bytearray(issuerID)
    data.extend(guID)
    data.extend(encoded_key)
    data.extend(roleID)
    signature = private_key.sign(bytes(data), ec.ECDSA(hashes.SHA256()))

    print("Signature: \n" + str(signature) + ", length " + str(len(signature)))
    print("Pubkey: \n" + str(pubkey) + ", length " + str(len(pubkey)))

    # TODO: Is it in the correct format?
    encoder.write(bytes(signature), 0x5F37)

    # role ID: 0x00 for card application key CVC
    encoder.write(roleID, 0x5F4C)

    print([i for i in encoder.output()])

    return encoder.output()


def send_cvc(connection, cvc):
    set_cvc_apdu = [0x80,  # CLA 80 - user defined.
                    0x22,  # INS 22 - Send formatted CVC.
                    0x00,  # P1  00 - unused
                    0x00,  # P2  00 - unused
                    len(cvc)]  # Total data length
    set_cvc_apdu.extend(cvc)
    print("CVC: " + str([i for i in cvc]))
    print("cvc apdu: " + str(set_cvc_apdu))

    data, sw1, sw2 = connection.transmit(set_cvc_apdu)
    print(hex(sw1) + ", " + hex(sw2))


# SHA-256, input val as byte array, generate 256-bit hash code as byte array.
def hashfun(val):
    hash_obj = hashlib.sha256()
    hash_obj.update(val)
    return hash_obj.digest()

# Initialise key
# TODO: check if already initialised and saved.
if os.path.exists("/Users/Ben/Desktop/part_II_project/Project/code/Python/HostAppOpt/privkey"):
    key_file = open("/Users/Ben/Desktop/part_II_project/Project/code/Python/HostAppOpt/privkey", mode='r+b')
    priv_bytes = key_file.read()
    priv = load_der_private_key(priv_bytes, None, default_backend())
else:
    priv = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
    priv_bytes = priv.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
    key_file = open("/Users/Ben/Desktop/part_II_project/Project/code/Python/HostAppOpt/privkey", mode='w+b')
    key_file.write(priv_bytes)
    pub = priv.public_key()
    pub_bytes = pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    pubkey_file = open("/Users/Ben/Desktop/part_II_project/Project/code/Python/HostAppOpt/root_pubkey", mode='w+b')
    pubkey_file.write(pub_bytes)
    # TODO: Store public key.


print("\n\nISSUING PROCESS")
cardRequest = CardRequest(timeout=None)
cardservice = cardRequest.waitforcard()

connection = cardservice.connection
cardservice.connection.connect()

# Select the OPACITY applet
select(connection)

# Format CVC from information obtained from the card.
cvc = format_cvc(connection, priv)

# Upload the CVC onto the card.
send_cvc(connection, cvc)

card_id = hashfun(cvc)[:8]

print("CVC length: " + str(len(cvc)))
#id_file = open("trusted_card_id.txt")


# TODO: Calculate ID from CVC, and save it as an approved card.
