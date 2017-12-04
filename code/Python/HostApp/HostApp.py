# This is the application that authenticates a card
import hashlib
import struct
from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, \
                                                         PrivateFormat, \
                                                         NoEncryption, \
                                                         PublicFormat, \
                                                         load_der_public_key

from cryptography.hazmat.primitives.asymmetric import ec
import asn1


from smartcard.CardRequest import CardRequest

# Later allow this to be programmed by user.
# Represent as 8B value.
global id_h
id_h = 1


def kdf(z, datalen, info):
    hashlen = 32
    # Generate 256b hashes until required length of key material is generated.
    iterations = (datalen / hashlen)
    if datalen % hashlen != 0:
        iterations = iterations + 1

    hashinput = bytes([0, 0, 0, 0])
    hashinput.extend(z)
    hashinput.extend(info)
    output = bytes()

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
def ec_dh(privkey_host, pubkey_card):
    # Should be stock ec_dh function to use.
    return privatekey_host.exchange(ec.ECDH(), pubkey_card)


def concat(a, b, c, d):
    ret = a
    ret.extend(b)
    ret.extend(c)
    ret.extend(d)
    return ret


# NIST 800-38B AES-128 based MAC algorithm.
# TODO: Ensure it is AES 128 and not some other AES
def verify_mac(mac, msg, sk_cfrm):
    c = cmac.CMAC(algorithms.AES(sk_cfrm), backend=default_backend())
    c.update(msg)

    # TODO: This throws exception if false. Handle somewhere.
    # Raises InvalidSignature or TypeError.
    c.verify(mac)


# Input byte array (obtained from APDU), split into 16B N_c, 128b mac, C_c
def extract_fields(data):
    nonce = data[:16]
    mac = data[16:32]
    cvc = data[32:]
    return nonce, mac, cvc


# First action taken by card when new card conencts.
# Returns string-format arrays
def gen_keys():
    # Generate keypair using NIST P-256 curve, encoding using DER.
    priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
    #d_h = priv.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
    pub = priv.public_key()
    #Q_h = pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return priv, pub


class client:
    # init method should provide class with basic starting parameters
    # e.g. host ID.

    # Extract Q_c from c_c, and validate Q_c belongs to EC domain.
    # c_c in Basic Encoding Rules (BER) format.
    def cvc_extract(self, c_c):
        decoder = asn1.Decoder()
        decoder.start(c_c)

        # TODO: Or does the first call return the entire block?
        tag, profile_id = decoder.read()
        assert tag == 43, ("Expected credential profile identifier tag 43, "
                           "got %d" % tag)
        assert profile_id == 0x80, "Unsupported version %d" % profile_id

        # Key issuer ID
        tag, issuerID = decoder.read()
        assert tag == 2, "Expected integer tag 2, got %d" % tag
        self.issuerID = issuerID

        tag, guid = decoder.read()
        assert tag == 32, "Expected GUID tag 32, got %s" % tag
        # self.guid = guid

        # Return compound type.
        tag, pubkey_der = decoder.read()
        assert tag == 72, "Expected card public key tag 72, got %d" % tag
        # TODO: validate public key belongs to EC domain
        self.Q_c = load_der_public_key(pubkey_der)

        tag, sig = decoder.read()
        assert tag == 55, "Expected digital signature tag 55, got %d" % tag

        # Role of key contained in this CVC
        tag, roleID = decoder.read()
        assert tag == 76, "Expected role ID tag 76, got %d" % tag

    def process_card(self):
        cardRequest = CardRequest(timeout=None)
        cardservice = cardRequest.waitforcard()

        connection = cardservice.connection
        cardservice.connection.connect()

        applet_select = [0x00,  # CLA 00 = ISO7816-4 command
                         0xA4,  # INS A4 = SELECT
                         0x04,  # P1 04 = select by name
                         0x00,  # P2 00 = first or only occurrence
                         0x06,  # Lc 06 = 6 bytes in data field
                         0xD4, 0xD4, 0xD4, 0xD4, 0xD4, 0xD4]  # Applet ID

        data, sw1, sw2 = connection.transmit(applet_select)
        # TODO: expect sw1,sw2 is success. If not, throw exception.

        # Gen keys, send id and host public key.
        self.d_h, self.Q_h = gen_keys()

        # TODO: Add auth request data including ID_h (host ID) || Q_h (public key)
        auth_request = [0x80,  # CLA 80 - user defined .
                        0x20,  # INS 20 - Auth request.
                        0x01,  # P1  01 - length of host ID in bytes
                        0x00,  # P2  00 - unused
                        0x02,  # Total data length
                        0x01, 0x00,  # Data - ID followed by public key TODO
                        0x01]  # Expected return length. TODO.

        data, sw1, sw2 = connection.transmit(auth_request)
        self.authenticate(extract_fields(data))

    # Action taken when response from card received.
    # c_c: Card Verifiable Credential authenticating Q_c.Contains Q_c somehow.
    def authenticate(self, nonce_c, authcryptogram, c_c):
        # Obtain card ID. id_c represented as bytes object.
        id_c = truncate8(hashfun(bytes(c_c)))

        # TODO
        self.cvc_extract(c_c)

        # Derive shared secret from card's public key, host private key.
        z = ec_dh(self.d_h, self.Q_c)

        # zeroise d_h
        d_h = 0

        # keydatalen length of secret keying material to be derived. Limited by
        # hashlen.
        # info is context-specific data. See 800-56A 5.8.1.2.
        sk_cfrm, sk_mac, sk_enc, sk_rmac, z_next =
        keys = kdf(z, keydatalen, info)
        sk_cfrm = keys[0:16]
        sk_mac = keys[16:32]
        sk_enc = keys[32:48]
        sk_rmac = keys[48:64]
        z_next = keys[64:80]

        # zeroise z
        z = 0

        # If fails, throw auth error.
        inputs = concat(bytes("KC_1_V"), id_c, id_h, truncate16(self.Q_h))
        checkval = C_MAC(sk_cfrm, inputs)
        check(authcryptogram, checkval)

        # zeroise
        sk_cfrm = 0

        # For additional commands use secure messaging with SKmac and SKenc.
