from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.asymmetric import ec
import asn1
from cryptography.hazmat.backends import default_backend


def gen_keys():
    # Generate keypair using NIST P-256 curve, encoding using DER.
    priv = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
    pub = priv.public_key()
    return priv, pub


def get_public_bytes(Q_h):
    pubkey_h_arr = Q_h.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

    decoder = asn1.Decoder()
    decoder.start(pubkey_h_arr)

    decoder.enter()
    decoder.enter()
    # Skip over '1.2.840.10045.3.1'
    tag, val = decoder.read()
    tag, val = decoder.read()
    decoder.leave()
    # Skip over object identifier, to public key bitstring.
    tag, val = decoder.read()

    # Remove initial 0x04 or 0x0004 from the bitstring to get the correct
    # format. Extract X value (first 32B)
    if val[0] == 0:
        pubkey_h_arr = val[2:34]
    else:
        pubkey_h_arr = val[1:33]
    decoder.leave()
    return pubkey_h_arr


def get_private_bytes(d_h):
    priv_bytes = d_h.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
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


# X co-ordinate of base point G.
G_arr = [0x6B, 0x17, 0xD1, 0xF2,
         0xE1, 0x2C, 0x42, 0x47,
         0xF8, 0xBC, 0xE6, 0xE5,
         0x63, 0xA4, 0x40, 0xF2,
         0x77, 0x03, 0x7D, 0x81,
         0x2D, 0xEB, 0x33, 0xA0,
         0xF4, 0xA1, 0x39, 0x45,
         0xD8, 0x98, 0xC2, 0x96]
#         0x4F, 0xE3, 0x42, 0xE2,  # Start of y co-ordinate.
#         0xFE, 0x1A, 0x7F, 0x9B,
#         0x8E, 0xE7, 0xEB, 0x4A,
#         0x7C, 0x0F, 0x9E, 0x16,
#         0x2B, 0xCE, 0x33, 0x57,
#         0x6B, 0x31, 0x5E, 0xCE,
#         0xCB, 0xB6, 0x40, 0x68,
#         0x37, 0xBF, 0x51, 0xF5]

# Prime number (n) representing the order of G.
prime_arr = [0xFF, 0xFF, 0xFF, 0xFF,
             0x00, 0x00, 0x00, 0x00,
             0xFF, 0xFF, 0xFF, 0xFF,
             0xFF, 0xFF, 0xFF, 0xFF,
             0xBC, 0xE6, 0xFA, 0xAD,
             0xA7, 0x17, 0x9E, 0x84,
             0xF3, 0xB9, 0xCA, 0xC2,
             0xFC, 0x63, 0x25, 0x51]

p2rime_arr = [0xFF, 0xFF, 0xFF, 0xFF,
             0x00, 0x00, 0x00, 0x01,
             0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00,
             0xFF, 0xFF, 0xFF, 0xFF,
             0xFF, 0xFF, 0xFF, 0xFF,
             0xFF, 0xFF, 0xFF, 0xFF]


# Generate key pair.
enc_priv, enc_pub = gen_keys()

# Get DER byte representations and extract the key data.
priv_card = get_private_bytes(enc_priv)
pub_card = get_public_bytes(enc_pub)

# Get relevant domain parameters as integers.
G = int.from_bytes(G_arr, byteorder='big')
prime = int.from_bytes(prime_arr, byteorder='big')
print(prime)
print(hex(G))
print(hex(prime))

# Get integer representations of key pair. (Only need X co-ordinate of Q)
Q = int.from_bytes(pub_card, byteorder='big')
d = int.from_bytes(priv_card, byteorder='big')
print(hex(d))
print(hex(Q))

print("\nThe following should be equal:")
print((G * d) % prime)
print(Q)
