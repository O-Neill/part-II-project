# This is the application that authenticates a card
import hashlib
import time
import asn1
import sys
import os

from smartcard.CardRequest import CardRequest

import cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.serialization import Encoding, \
                                                         PrivateFormat, \
                                                         NoEncryption, \
                                                         PublicFormat

sys.path.append(os.path.join(sys.path[0], '../lib/python-rubenesque'))
from rubenesque.curves.sec import secp256r1

# TODO: Get better info on max CVC length (and why it varies)
global max_cvc_len
max_cvc_len = 220


# z is int type.
def kdf(z, datalen, info):
    hashlen = 32
    # Generate 256b hashes until required length of key material is generated.
    iterations = (datalen // hashlen)
    if datalen % hashlen != 0:
        iterations = iterations + 1

    hashinput = bytearray([0, 0, 0, 0])
    hashinput.extend(z)
    hashinput.extend(info)
    output = bytearray()

    for x in range(1, iterations + 1):
        hashinput[3] = x
        output.extend(hashfun(hashinput))

    return output[0:datalen]


# SHA-256, input val as byte array, generate 256-bit hash code as byte array.
def hashfun(val):
    hash_obj = hashlib.sha256()
    hash_obj.update(val)
    return hash_obj.digest()


# Extract leftmost 8 bytes of data. (input is string, likely 256 bits)
def truncate8(val):
    # TODO: Check length
    return(val[0:8])


def truncate16(val):
    return(val[0:16])


# Compute shared secret, Diffie-Hellman style.
# Both ends use secret keys to encrypt same data in different order to obtain
# shared secret.
# See ECC based key agreement, 800-56A
# Returns shared secret as an int type.
# Input privkey as array representing int, pubkey as array representing point.
def ec_dh(priv_host, pub_card):
    Q = secp256r1.create(int.from_bytes(pub_card[1:33], byteorder='big'),
                         int.from_bytes(pub_card[33:65], byteorder='big'))
    d = int.from_bytes(priv_host, byteorder='big')

    z = Q * d
    secret = z.x
    z_bytes = secret.to_bytes(length=(secret.bit_length() + 7) // 8, byteorder='big')
    return z_bytes


def concat(a, b, c, d):
    ret = a
    ret.extend(b)
    ret.extend(c)
    ret.extend(d)
    return ret


# NIST 800-38B AES-128 based MAC algorithm.
# TODO: Ensure it is AES 128 and not some other AES
def verify_mac(mac, msg, sk_cfrm):
    d = cmac.CMAC(algorithms.AES(bytes(sk_cfrm)), backend=default_backend())
    d.update(bytes(msg))
    mac = d.finalize()

    c = cmac.CMAC(algorithms.AES(bytes(sk_cfrm)), backend=default_backend())
    c.update(bytes(msg))

    # TODO: This throws exception if false. Handle somewhere.
    # Raises InvalidSignature or TypeError.
    try:
        c.verify(bytes(mac))
        return True
    except cryptography.exceptions.InvalidSignature:
        return False


# Input byte array (obtained from APDU), split into 16B N_c, 128b mac, C_c
def extract_fields(data):
    nonce = data[:16]
    mac = data[16:32]
    cvc = data[32:]
    return nonce, mac, cvc

def get_public_bytes(Q_h):
    pubkey_h_arr = Q_h.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

    decoder = asn1.Decoder()
    decoder.start(pubkey_h_arr)

    decoder.enter()
    decoder.enter()
    # Skip over algorithm IDs.
    tag, val = decoder.read()
    tag, val = decoder.read()
    decoder.leave()
    # Skip over object identifier, to public key bitstring.
    tag, val = decoder.read()

    # Remove initial 0x04 or 0x0004 from the bitstring to get the correct
    # format. Extract X value (first 32B)
    if val[0] == 0:
        return val[1:66]
    else:
        return val

def get_private_bytes(d_h):
    priv_bytes = d_h.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
    #print(priv_bytes)
    decoder = asn1.Decoder()
    decoder.start(priv_bytes)
    decoder.enter()

    # Skip over version and algorithm ID.
    decoder.read()
    decoder.read()

    tag, privkey_der = decoder.read()

    decoder.start(privkey_der)
    decoder.enter()
    # Skip over version (should be 1)
    tag, val = decoder.read()

    tag, privkey = decoder.read()
    return privkey

# First action taken by card when new card conencts.
# Returns string-format arrays
def gen_keys():
    # Generate keypair using NIST P-256 curve, encoding using DER.
    priv = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
    #d_h = priv.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
    pub = priv.public_key()
    #Q_h = pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return priv, pub


class Client:
    # Initialise client with 8B bytearray containing id.
    def __init__(self, id_h):
        # TODO: Check id length
        self.id = id_h

    # Extract Q_c from c_c, and validate Q_c belongs to EC domain.
    # c_c in Basic Encoding Rules (BER) format.
    def cvc_extract(self, c_c):
        decoder = asn1.Decoder()
        decoder.start(bytes(c_c))

        # TODO: Or does the first call return the entire block?
        tag, profile_id = decoder.read()
        assert tag[0] == 0x5F29, ("Expected credential profile identifier tag "
                                  "0x5F29, got " + hex(tag[0]))

        assert profile_id == bytes([0x80]), "Unsupported version %s" % hex(profile_id)

        # Key issuer ID
        tag, issuerID = decoder.read()
        assert tag[0] == 0x42, "Expected integer tag 0x42, got %s" % hex(tag[0])
        self.issuerID = issuerID

        tag, guid = decoder.read()
        assert tag[0] == 0x5F20, "Expected GUID tag 0x5F20, got %s" % hex(tag[0])
        # self.guid = guid

        # Return compound type.
        tag, pubkey_der = decoder.read()
        assert tag[0] == 0x7F49, "Expected card public key tag 0x7F49, got %s" % hex(tag[0])
        # TODO: validate public key belongs to EC domain
        key_decoder = asn1.Decoder()
        key_decoder.start(pubkey_der)
        tag, alg = key_decoder.read()
        assert tag[0] == 0x06, "Expected algorithm tag 0x06, got %s" % hex(tag[0])
        assert alg == '1.2.840.10045.3.1.7', "Expected algorithm ID 1.2.840.10045.3.1.7, got %s" % alg
        tag, key = key_decoder.read()
        assert tag[0] == 0x86, "Expected key bytes tag 0x86, got %s" % hex(tag[0])
        self.card_pubkey = key

        tag, sig = decoder.read()
        assert tag[0] == 0x5F37, "Expected digital signature tag 0x5F37, got %s" % hex(tag[0])

        # Role of key contained in this CVC
        tag, roleID = decoder.read()
        assert tag[0] == 0x5F4C, "Expected role ID tag 0x5F4C, got %s" % hex(tag[0])

    def process_card(self):
        global max_cvc_len
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
        print("SELECT")
        print(hex(sw1) + ", " + hex(sw2))
        # TODO: expect sw1,sw2 is success. If not, throw exception.

        # Gen keys, send id and host public key.
        # TODO: Should these be object fields? Or just temp variables?
        self.d_h, self.Q_h = gen_keys()

        # TODO: Break conversion from DER into separate function
        pubkey_h_arr = get_public_bytes(self.Q_h)

        datalen = len(self.id) + len(pubkey_h_arr) + 1
        print("datalen: " + str(datalen))

        auth_request = [0x80,  # CLA 80 - user defined .
                        0x20,  # INS 20 - Auth request.
                        len(pubkey_h_arr),  # P1 - length of host public key in bytes
                        0x00,  # P2  00 for normal, 01 for print val
                        datalen]  # Total data length
        # Data is host ID followed by ephemeral host public key.
        auth_request.extend(self.id)
        auth_request.extend(pubkey_h_arr)
        auth_request.append(0x01)  # Control byte 0x01 - use persistent binding.
        auth_request.append(32 + max_cvc_len)  # 16B nonce, 16B C-MAC, CVC expected.
        print("Auth request: " + str(auth_request))

        start = time.time()
        data, sw1, sw2 = connection.transmit(auth_request)
        end = time.time()
        print("AUTHENTICATE")
        print("Data length: " + str(len(data)))
        print("Data: " + str(data))
        print(hex(sw1) + ", " + hex(sw2))
        nonce, mac, cvc = extract_fields(data)
        print("Nonce: " + str(nonce))
        print("MAC: " + str(mac))
        print("CVC: " + str(cvc))
        print("Time taken: " + str(end - start) + " seconds")
        self.authenticate(nonce, mac, cvc)

    # Action taken when response from card received.
    def authenticate(self, nonce_c, authcryptogram, c_c):
        # Obtain card ID. id_c represented as bytes object.
        # TODO

        id_c = truncate8(hashfun(bytes(c_c)))
        print("Card ID: " + str([i for i in id_c]))

        # TODO
        self.cvc_extract(c_c)

        # Derive shared secret from card's public key, host private key.
        # TODO: should I use TraditionalOpenSSL encoding format?
        privkey = get_private_bytes(self.d_h)

        print("Host Private key: " + str([i for i in privkey]))
        print("Length: " + str(len(privkey)))
        print()

        #pub = self.get_public_bytes()
        #print("Host Public key: " + str([i for i in pub]))
        print("Card pubkey: " + str([i for i in self.card_pubkey]))
        z = ec_dh(privkey, self.card_pubkey)

        print("Host secret: " + str([i for i in z]))


        # zeroise d_h
        self.d_h = 0

        # keydatalen length of secret keying material to be derived. Limited by
        # hashlen.
        # info is context-specific data. See 800-56A 5.8.1.2.
        keydatalen = 5 * 16
        # TODO: Use correct info.
        info = bytes()
        keys = kdf(z, keydatalen, info)
        sk_cfrm = keys[0:16]
        sk_mac = keys[16:32]
        sk_enc = keys[32:48]
        sk_rmac = keys[48:64]
        z_next = keys[64:80]

        # zeroise z
        z = 0

        # If fails, throw auth error.
        pubkey_bytes = self.Q_h.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        inputs = concat(bytearray("KC_1_V", 'utf-8'), id_c, self.id, truncate16(pubkey_bytes))

        # TODO: Catch exception and handle.
        checkval = verify_mac(authcryptogram, inputs, sk_cfrm)
        print(checkval)
        # check(authcryptogram, checkval)

        # zeroise
        sk_cfrm = 0

        # For additional commands use secure messaging with SKmac and SKenc.


d_h, Q_h = gen_keys()

# TODO: Break conversion from DER into separate function
pubkey_h_arr = Q_h.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
# TODO: Should I remove unwanted algorithm identifiers from DER structure?

print("\n\nAUTHENTICATION PROCESS")

id_h = bytes([0, 0, 0, 0, 0, 0, 0, 1])
cl = Client(id_h)
import time
start = time.time()
cl.process_card()
end = time.time()
print("Time taken: " + str(end - start))
