# This is the application that authenticates a card
from ecdsa import SigningKey
import hashlib
import struct
from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.backends import default_backend
import asn1


from smartcard.CardRequest import CardRequest

# Later allow this to be programmed by user.
global id_h
id_h = 1


def str_to_byte_arr(arr):
    hexarr = [elem.encode("hex") for elem in arr]
    intarr = [int(elem, 16) for elem in hexarr]
    return intarr


# TODO: Not entirely sure if fmt should be little or big endian.
def bytes_to_num(bytearr):
    fmt = ">Q"  # big endian, 8B unsigned integer.
    arr = [int(elem, 16) for elem in bytearr]
    print arr
    packedarr = struct.unpack(">Q", bytearray(arr))[0]
    struct.unpack(fmt, packedarr)


# SHA-256, generate 256-bit hash code as string.
def hashfun(val):
    hash_obj = hashlib.sha256()
    hash_obj.update(val)
    return hash_obj.digest()


# Extract leftmost 8 bytes of data. (input is string, likely 256 bits)
def truncate8(val):
    truncated_arr = str_to_byte_arr(val)[0:8]
    bytearray(truncated_arr)
    return struct.unpack("<Q", bytearray(truncated_arr))[0]


# Compute shared secret, Diffie-Hellman style.
# Both ends use secret keys to encrypt same data in different order to obtain
# shared secret.
# See ECC based key agreement, 800-56A
def ec_dh(privkey_host, pubkey_card):
    pass


def concat(a, b, c, d):
    pass


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
    cvc = data[32:2]
    return nonce, mac, cvc


# First action taken by card when new card conencts.
def gen_keys():
    d_h = SigningKey.generate()  # Uses NIST 192p by default
    Q_h = d_h.get_verifying_key()
    return d_h, Q_h


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
        tag, pubkey_card = decoder.read()
        assert tag == 72, "Expected card public key tag 72, got %d" % tag
        # TODO: Do I need a new decoder here or does the next read() break it
        # down?

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
                         0x06,  # Lc 05 = 8 bytes in data field
                         0xD4, 0xD4, 0xD4, 0xD4, 0xD4, 0xD4]  # Applet ID

        data, sw1, sw2 = connection.transmit(applet_select)
        # TODO: expect sw1,sw2 is success. If not, throw exception.

        # Gen keys, send id and host public key.
        d_h, Q_h = gen_keys()

        # TODO: Add auth request data including ID_h (host ID) || Q_h (public key)
        auth_request = [0x80,  # CLA 80 - user defined .
                        0x01,  # INS 01 - Auth request.
                        0x01,  # P1  01 - length of host ID in bytes
                        0x00,  # P2  00 - unused
                        0x02,  # Total data length
                        0x01, 0x00,  # Data - ID followed by public key
                        0x01]  # Expected return length. TODO.

        data, sw1, sw2 = connection.transmit(auth_request)
        self.authenticate(extract_fields(data))

    # Action taken when response from card received.
    # c_c: Card Verifiable Credential authenticating Q_c.Contains Q_c somehow.
    def authenticate(self, nonce_c, authcryptogram, c_c):
        # Obtain card ID
        id_c = truncate8(hashfun(c_c))

        # TODO
        Q_c = extract_key(c_c)

        # Derive shared secret from card's public key, host private key.
        z = ec_dh(d_h, Q_c)

        # zeroise d_h
        d_h = 0

        # keydatalen length of secret keying material to be derived. Limited by
        # hashlen.
        # info is context-specific data. See 800-56A 5.8.1.2.
        sk_cfrm, sk_mac, sk_enc, sk_rmac, z_next = kdf(z, keydatalen, info)

        # zeroise z
        z = 0

        # If fails, throw auth error.
        inputs = concat("KC_1_V", id_c, id_h, truncate16(Q_h))
        checkval = C_MAC(sk_cfrm, inputs)
        check(authcryptogram, checkval)

        # zeroise
        sk_cfrm = 0

        # For additional commands use secure messaging with SKmac and SKenc.
