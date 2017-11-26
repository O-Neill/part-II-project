# TODO: Issue card with CVC.
import asn1

# NOTE: Overview - get card to generate keys, send public.
# This app will then send CVC containing public key. No handy way to do it on
# Java Card and would probably be quicker on host anyway.

# TODO: Get public key from card instead of this.
pubkey = bytearray(64)
print(pubkey)


def pubkey():
    # First suggested Object ID. Not sure if best.
    # Corresponds to 1.3.132.0.33
    objID = 0x2B81040021
    keyencoder = asn1.Encoder()
    encoder.start()
    encoder.write(objID, 0x06)
    key = bytearray([0x04])
    key.extend(pubkey)
    encoder.write(bytes(key), 0x86)
    return encoder.output()


# TODO: use proper values (not just test ones)
# 6B Issuer ID, 2B Issuer Key ID (for issued CVC)
issuerID = [0, 0, 0, 0, 0, 0, 0, 1]

# Globally Unique ID - Application specific, identifies card or cardholder.
# Could be generated from a counter.
guID = [0, 0, 0, 0, 0, 0, 0, 0, 0, 1]

encoder = asn1.Encoder()
encoder.start()

encoder.write(bytes([0x80]), 0x5F29)
encoder.write(bytes(issuerID), 0x42)
encoder.write(bytes(guID), 0x5F20)



encoded_bytes = encoder.output()

decoder = asn1.Decoder()
decoder.start(encoded_bytes)
tag, value = decoder.read()
print(tag)
print(value)
