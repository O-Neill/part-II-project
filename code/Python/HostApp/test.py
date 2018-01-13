from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.asymmetric import ec
import asn1
from cryptography.hazmat.backends import default_backend
import sys
import os

sys.path.append(os.path.join(sys.path[0], '../lib/python-rubenesque'))
from rubenesque.curves.sec import secp256r1


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



# Generate key pairs.
enc_priv, enc_pub = gen_keys()
enc_priv2, enc_pub2 = gen_keys()

# Get DER byte representations and extract the key data.
priv = get_private_bytes(enc_priv)
priv2 = get_private_bytes(enc_priv2)
pub = get_public_bytes(enc_pub)
pub2 = get_public_bytes(enc_pub2)

print("Private: " + str([i for i in priv]))
print("Public: " + str([i for i in pub2]))

Q = secp256r1.create(int.from_bytes(pub[1:33], byteorder='big'),
                     int.from_bytes(pub[33:65], byteorder='big'))
d = int.from_bytes(priv, byteorder='big')
Q2 = secp256r1.create(int.from_bytes(pub2[1:33], byteorder='big'),
                      int.from_bytes(pub2[33:65], byteorder='big'))
d2 = int.from_bytes(priv2, byteorder='big')

z = Q2 * d
z2 = Q * d2

print(z == z2)
print("Secret: " + str([i for i in z.x.to_bytes(length=(z.x.bit_length() + 7) // 8, byteorder='big')]))
#print(z. < 2**32)
