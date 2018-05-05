# This is the application that authenticates a card
import hashlib
import time
import asn1
import sys
import os
import PBStore

from smartcard.CardRequest import CardRequest

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.serialization import Encoding, \
                                                         PrivateFormat, \
                                                         NoEncryption, \
                                                         PublicFormat, \
                                                         load_der_public_key
from cryptography.exceptions import InvalidSignature

sys.path.append(os.path.join(sys.path[0], '../lib/python-rubenesque'))
from rubenesque.curves.sec import secp256r1

# TODO: Get better info on max CVC length (and why it varies)
global max_cvc_len
max_cvc_len = 220

global RET_GUID
RET_GUID = 0x10
global PB
PB = 0x01
global PB_INIT
PB_INIT = 0x02
global NO_PB
NO_PB = 0x00

global applet_id
applet_id = [0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6]


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
    return secret


def concat(a, b, c, d):
    ret = a
    ret.extend(b)
    ret.extend(c)
    ret.extend(d)
    return ret


# NIST 800-38B AES-128 based MAC algorithm.
# TODO: Ensure it is AES 128 and not some other AES
def eval_mac(msg, sk_cfrm):
    c = cmac.CMAC(algorithms.AES(bytes(sk_cfrm)), backend=default_backend())
    c.update(bytes(msg))
    return c.finalize()


# Input byte array (obtained from APDU), split into 16B N_c, 128b mac, C_c
def extract_fields(data):
    global RET_GUID
    cb = data[0]
    nonce = data[1:17]
    mac = data[17:33]
    if (cb & RET_GUID):
        enc_guid = data[33:49]
        iccID = data[49:]
    else:
        enc_guid = []
        iccID = data[33:]

    return cb, nonce, mac, enc_guid, iccID


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
    pub = priv.public_key()
    return priv, pub


def create_apdu(cla, ins, p1, p2, data, ret_len=None):
    apdu = [cla, ins, p1, p2, len(data)]
    apdu.extend(data)
    if ret_len is not None:
        if ret_len == "max":
            apdu.extend([0, 0])
        else:
            apdu.append(ret_len)
    return apdu


class Client:
    # Initialise client with 8B bytearray containing id.
    def __init__(self, id_h, filename, root_pubkey, mask):
        self.store = PBStore.Store(filename)
        # TODO: Check id length
        self.id = id_h
        self.root_pubkey = root_pubkey
        self.mask = mask

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
        self.guid = guid

        # Return compound type.
        tag, pubkey_der = decoder.read()
        assert tag[0] == 0x7F49, "Expected card public key tag 0x7F49, got %s" % hex(tag[0])
        # TODO: validate public key belongs to EC domain
        key_decoder = asn1.Decoder()
        key_decoder.start(pubkey_der)
        tag, alg = key_decoder.read()
        assert tag[0] == 0x06, "Expected algorithm tag 0x06, got %s" % hex(tag[0])
        assert alg == '1.2.840.10045.3.1.7', "Expected algorithm ID 1.2.840.10045.3.1.7, got %s" % alg
        tag, pubkey_raw = key_decoder.read()
        assert tag[0] == 0x86, "Expected key bytes tag 0x86, got %s" % hex(tag[0])
        self.card_pubkey = pubkey_raw

        tag, signature = decoder.read()
        assert tag[0] == 0x5F37, "Expected digital signature tag 0x5F37, got %s" % hex(tag[0])

        # Role of key contained in this CVC
        tag, roleID = decoder.read()
        assert tag[0] == 0x5F4C, "Expected role ID tag 0x5F4C, got %s" % hex(tag[0])

        return issuerID, guid, pubkey_der, pubkey_raw, signature, roleID

    def process_card(self):
        global max_cvc_len
        global PB
        global PB_INIT
        global applet_id
        global NO_PB
        cardRequest = CardRequest(timeout=None)
        cardservice = cardRequest.waitforcard()

        connection = cardservice.connection
        cardservice.connection.connect()

        # CLA 00 = ISO7816-4 command
        # INS A4 = SELECT
        # P1 04 = select by name
        # P2 00 = first or only occurrence
        # Lc 06 = 6 bytes in data field
        applet_select = create_apdu(0x00, 0xA4, 0x04, 0x00, applet_id)

        data, sw1, sw2 = connection.transmit(applet_select)
        print("SELECT")
        print(hex(sw1) + ", " + hex(sw2))
        # TODO: expect sw1,sw2 is success. If not, throw exception.

        # Gen keys, send id and host public key.
        # TODO: Should these be object fields? Or just temp variables?
        self.d_h, self.Q_h = gen_keys()

        # TODO: Break conversion from DER into separate function
        pubkey_h_arr = get_public_bytes(self.Q_h)

        # This terminal supports PB
        cb = NO_PB

        in_dat = [b for b in self.id]
        in_dat.extend(pubkey_h_arr)
        print(len(pubkey_h_arr))
        in_dat.append(cb)
        # CLA 80 = user defined. INS 20 = Auth request.
        auth_request = create_apdu(0x80, 0x20, 0x00, 0, in_dat, 255)

        start = time.time()
        data, sw1, sw2 = connection.transmit(auth_request)
        end = time.time()
        print("Time taken for card: " + str(end - start) + " seconds")
        print("AUTHENTICATE")
        print(hex(sw1) + ", " + hex(sw2))
        cb_card, nonce, mac, EncGuid, iccID = extract_fields(data)
        return self.authenticate(cb_card, nonce, mac, EncGuid, iccID)

    # Action taken when response from card received.
    # Function performs functionality of the SAM in the protocol.
    def authenticate(self, CB_card, nonce_c, authcryptogram, EncGuid, iccID):
        # Obtain card ID. id_c represented as bytes object.
        # TODO
        print("entered Authenticate()")
        global PB
        global PB_INIT
        global RET_GUID
        global NO_PB
        print("Card CB: " + str(CB_card))
        if CB_card & 0x0F == PB:
            print("ICC using previously saved Z")
            # ICC using previously saved Z
            # S3
            id_c_arr = bytes(iccID)
            id_c = int.from_bytes(bytes(iccID), byteorder='big')
            # TODO: Maybe should load CVC from store to get issuerID, card_pubkey.

            # S4, S5, S6
            if self.store.contains(id_c) is False:
                # PB was chosen but no matching register entry exists.
                # zeroise privkey
                self.d_h = 0
                # return CB_H = PB_INIT (Restart OPACITY)
                print("RETURN PB_INIT")
                return PB_INIT
            else:
                # In the standard this was done in every case, but this is wrong
                # as it means the card accesses the PB reg even if PB not used.
                # Moved here to fix the issue.
                # S10
                # Obtain z from id_c PB registry
                z, cvc = self.store.getCardInfo(id_c)
                issuerID, guid, pubkey_der, pubkey_raw, signature, roleID = self.cvc_extract(cvc)
                print("Accessed PB registry")
        else:
            print("ICC computed a new Z")
            # ICC computed a new Z
            # S2
            id_c_arr = hashfun(bytes(iccID))[:8]
            id_c = int.from_bytes(id_c_arr, byteorder='big')
            cvc = iccID

            print("Computing a new Z")
            # TODO: Should this really only be completed if no register entry?
            # Surely it doesn't matter whether there's a register entry if
            # the card didn't specify that it supports PB?

            # S8, S9
            # If not registered,
            issuerID, guid, card_key_der, card_key_raw, signature, roleID = self.cvc_extract(cvc)
            privkey = get_private_bytes(self.d_h)
            z = ec_dh(privkey, card_key_raw)
            self.d_h = 0

        pubkey_bytes = self.Q_h.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        decoder = asn1.Decoder()
        decoder.start(pubkey_bytes)
        decoder.enter()
        decoder.read()
        tag, val = decoder.read()
        pubkey_bytes = val[1:]

        # keydatalen length of secret keying material to be derived. Limited by
        # hashlen.
        # info is context-specific data. See 800-56A 5.8.1.2.
        # S11
        keydatalen = 4 * 16 + 32
        info = bytearray(id_c_arr)
        info.extend(self.id)
        info.extend(bytes(pubkey_bytes[:16]))
        info.extend(bytes(nonce_c))
        z_bytes = z.to_bytes(length=(z.bit_length() + 7) // 8, byteorder='big')
        keys = kdf(z_bytes, keydatalen, info)
        sk_cfrm = keys[0:16]
        sk_mac = keys[16:32]
        sk_enc = keys[32:48]
        sk_rmac = keys[48:64]
        z_next = keys[64:]

        # S12 - zeroise z
        z = 0

        # S13 - Verify authentication code
        # If fails, throw auth error.

        inputs = concat(bytearray("KC_1_V", 'utf-8'), id_c.to_bytes(8, byteorder='big'), self.id, pubkey_bytes[:16])

        # TODO: Catch exception and handle by returning AUTH_ERROR
        print("Card CMAC")
        print(authcryptogram)
        host_cmac = [i for i in eval_mac(inputs, sk_cfrm)]
        print("Host CMAC")
        print(host_cmac)
        checkval = (host_cmac == authcryptogram)
        print("AUTH SUCCESS: " + str(checkval))

        # S14 - zeroise
        sk_cfrm = 0

        if CB_card & PB_INIT:
            # S15
            print("Adding record")
            print("ID: " + str(id_c))
            print("Z: " + str(z_next))
            self.store.addRecord(id_c, bytes(z_next), bytes(cvc))

        if CB_card & 0x0F != NO_PB:
            # S16
            CB_host = PB
        else:
            # S17
            CB_host = NO_PB

        # TODO: Check blacklist to see if ID is barred.

        if CB_card & RET_GUID:
            # TODO
            # Unsure about the following:
            #guid = EncGuid XOR AES(sk_enc, IV)
            #build C_ICC from C_ICC* amd GUID
            #Verify C_ICC signature using ECDSA
            # S21

            # data = issuerID, GUID, encoded_key, roleID
            data = issuerID
            data.append(guid)
            data.append(card_key_der)
            data.append(roleID)

            CB_H |= RET_GUID


            # If the GUID doesn't permit access to this terminal, return.
            if (int.from_bytes(self.mask, byteorder='big') ^ int.from_bytes(guid, byteorder='big')) == 0:
                # TODO: Consult whitelist first
                return False

            try:
                self.root_pubkey.verify(signature, data, ec.ECDSA(hashes.SHA256()))
            except InvalidSignature:
                return False

        else:
            # S22
            guid = None

        # S23
        return True
        # For additional commands use secure messaging with SKmac and SKenc.


# Load the root key
root_file = open("/Users/Ben/Desktop/part_II_project/Project/code/Python/HostAppOpt/root_pubkey", mode='r+b')
root_bytes = root_file.read()

root = load_der_public_key(root_bytes, default_backend())
id_h = bytes([0, 0, 0, 0, 0, 0, 0, 1])
mask = bytes([255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255])
cl = Client(id_h, "/Users/Ben/Desktop/part_II_project/Project/code/Python/HostAppOpt/store.xml", root, mask)

while(True):
    print("\n\nAUTHENTICATION PROCESS")

    # Generate ephemeral keypair
    d_h, Q_h = gen_keys()

    # TODO: Break conversion from DER into separate function
    pubkey_h_arr = Q_h.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    # TODO: Should I remove unwanted algorithm identifiers from DER structure?

    start = time.time()
    result = cl.process_card()
    if result == PB_INIT:
        # TODO: Deal with.
        quit(0)
    print("Time taken overall: " + str(time.time() - start))
    quit()
