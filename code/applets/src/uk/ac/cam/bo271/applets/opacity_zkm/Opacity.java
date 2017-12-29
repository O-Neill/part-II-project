package uk.ac.cam.bo271.applets.opacity_zkm;

import javacard.framework.*;
import javacard.security.MessageDigest;
import javacard.security.KeyBuilder;
import javacard.security.PublicKey;
import javacard.security.PrivateKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyPair;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacard.security.AESKey;
import javacard.security.ECPublicKey;
import javacard.security.ECPrivateKey;
import javacard.security.CryptoException;

// TODO: Consider what happens if deselect at any point. May need atomic
// transactions provided by JCSystem.
// Make more efficient by avoiding creating new arrays.

// TODO: Could call relevant init() methods during installation (e.g. for CMAC)
// to improve runtime efficiency.

public class Opacity extends Applet {
    private byte[] cvc;
    private byte[] id_card;
    private ECConfig m_ecc;
    private boolean DEBUG = false;

    // secp256r1 curve parameters:
    // Field specification parameter.
    private static byte[] SECP256R1_P =
                              {(byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
                               0x00, 0x00, 0x00, (byte)0x01,
                               0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00,
                               (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
                               (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
                               (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF};

    // The 2 coefficients of the curve y^2 = x^3 + ax + b
    private static byte[] SECP256R1_A =
                              {(byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
                               0x00, 0x00, 0x00, (byte)0x01,
                               0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00,
                               (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
                               (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
                               (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFC};
    private static byte[] SECP256R1_B =
                              {(byte)0x5A, (byte)0xC6, (byte)0x35, (byte)0xD8,
                               (byte)0xAA, (byte)0x3A, (byte)0x93, (byte)0xE7,
                               (byte)0xB3, (byte)0xEB, (byte)0xBD, (byte)0x55,
                               (byte)0x76, (byte)0x98, (byte)0x86, (byte)0xBC,
                               (byte)0x65, (byte)0x1D, (byte)0x06, (byte)0xB0,
                               (byte)0xCC, (byte)0x53, (byte)0xB0, (byte)0xF6,
                               (byte)0x3B, (byte)0xCE, (byte)0x3C, (byte)0x3E,
                               (byte)0x27, (byte)0xD2, (byte)0x60, (byte)0x4B};

    // Base point of the curve (Uncompressed version, compressed isn't accepted)
    private static byte[] SECP256R1_G =
                              {(byte)0x04,
                               (byte)0x6B, (byte)0x17, (byte)0xD1, (byte)0xF2,
                               (byte)0xE1, (byte)0x2C, (byte)0x42, (byte)0x47,
                               (byte)0xF8, (byte)0xBC, (byte)0xE6, (byte)0xE5,
                               (byte)0x63, (byte)0xA4, (byte)0x40, (byte)0xF2,
                               (byte)0x77, (byte)0x03, (byte)0x7D, (byte)0x81,
                               (byte)0x2D, (byte)0xEB, (byte)0x33, (byte)0xA0,
                               (byte)0xF4, (byte)0xA1, (byte)0x39, (byte)0x45,
                               (byte)0xD8, (byte)0x98, (byte)0xC2, (byte)0x96,
                               (byte)0x4F, (byte)0xE3, (byte)0x42, (byte)0xE2,
                               (byte)0xFE, (byte)0x1A, (byte)0x7F, (byte)0x9B,
                               (byte)0x8E, (byte)0xE7, (byte)0xEB, (byte)0x4A,
                               (byte)0x7C, (byte)0x0F, (byte)0x9E, (byte)0x16,
                               (byte)0x2B, (byte)0xCE, (byte)0x33, (byte)0x57,
                               (byte)0x6B, (byte)0x31, (byte)0x5E, (byte)0xCE,
                               (byte)0xCB, (byte)0xB6, (byte)0x40, (byte)0x68,
                               (byte)0x37, (byte)0xBF, (byte)0x51, (byte)0xF5};

    // Prime number representing the order of G. Also referred to as R.
    private static byte[] SECP256R1_N =
                              {(byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
                               0x00, 0x00, 0x00, 0x00,
                               (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
                               (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
                               (byte)0xBC, (byte)0xE6, (byte)0xFA, (byte)0xAD,
                               (byte)0xA7, (byte)0x17, (byte)0x9E, (byte)0x84,
                               (byte)0xF3, (byte)0xB9, (byte)0xCA, (byte)0xC2,
                               (byte)0xFC, (byte)0x63, (byte)0x25, (byte)0x51};

    // Cofactor of the order of the fixed point G.
    private static short SECP256R1_H = 0x01;

    // 6B message string forming the start of the CMAC input as per NIST 800-56A.
    // Represents "KC_1_V" meaning party V provides the tag in unilateral key confirmation.
    private static byte[] MESSAGE_STRING = {(byte)75, (byte)67, (byte)95,
                                            (byte)49, (byte)95, (byte)86};

    private KeyPair kp;

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        Opacity applet = new Opacity();
        applet.register();
    }


    // NOTE: Could be made more efficient if it reads relevant part directly
    // from overall array (rather than copying into separate array).
    private void hash(byte[] input, short inOffset, short len, byte[] output, short outOffset) {
        // Initialise SHA-256 digest, don't allow sharing with other applets.
        // TODO: Check array lengths are valid.
        MessageDigest hash = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        hash.reset();
        hash.doFinal(input, inOffset, len, output, outOffset);
    }

    // Verify input key belongs to EC domain.
    private void validate_key(byte[] key) {
        // TODO Should be able to attempt to create Key object and catch
        // exception.
    }

    // Perform EC_DH algorithm using host public key and card private key
    // to acquire the shared secret.
    private byte[] get_secret(byte[] pubkey_host, APDU apdu) {
        // Should only contain X data.
        if (pubkey_host.length != 32) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        short keySize = 32;
        byte[] privKey = JCSystem.makeTransientByteArray(keySize, JCSystem.CLEAR_ON_DESELECT);
        short num_bytes = ((ECPrivateKey)kp.getPrivate()).getS(privKey, (short)0);
        if (num_bytes != keySize) {
            ISOException.throwIt(num_bytes);
        }

        byte[] buffer = apdu.getBuffer();
        if(buffer[ISO7816.OFFSET_P2] == 0x06) {
            send(privKey, (short)0, (short)32, apdu);
            return null;
        }

        // TODO: Calculate Z = h * d_a * Q_h
        Bignat d_a = new Bignat(privKey, m_ecc.bnh);
        Bignat Q_b = new Bignat(pubkey_host, m_ecc.bnh);
        Bignat z = new Bignat((short)(d_a.length() + Q_b.length()), JCSystem.CLEAR_ON_RESET, m_ecc.bnh);
        z.mult(d_a, Q_b);
        return z.as_byte_array();
    }
/*  Couldn't get library ECDH function to accept the public key value.
    private byte[] get_secret(byte[] pubkey_host) {
        // NOTE: Key agreement with cofactor multiplication. Is this what I want?
        KeyAgreement dh = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH, false);

        // TODO: Correct? or provide key in another form?
        dh.init(kp.getPrivate());

        // TODO: What's the smallest array I can use?
        byte temp[] = JCSystem.makeTransientByteArray((short)100, JCSystem.CLEAR_ON_DESELECT);

        // Throws CryptoException if pubkey formatted wrong.
        short len = 0;

        try {
            len = dh.generateSecret(pubkey_host, (short)0, (short)pubkey_host.length, temp, (byte)0);
        } catch (CryptoException e) {
            ISOException.throwIt((short)(e.getReason() + 0x1100));
        }
        if (len != 16) {
            ISOException.throwIt((short)(0x1600 + len));
        }


        byte[] output = new byte[len];
        Util.arrayCopy(temp, (byte)0, output, (short)0, len);
        return output;
    }
    */

    // Outputs key material in 'keys' array.
    public void kdf(byte[] secret, byte len, byte[] info, byte[] keys) {
        byte hashlen = 32;

        short hashinputlen = (short)(4 + secret.length + info.length);

        // NOTE: Is this overwritten by hash function?
        // NOTE: Initialised to 0?
        byte[] hashinput = new byte[hashinputlen];

        Util.arrayFillNonAtomic(hashinput, (short)0, (short)4, (byte)0x00);
        Util.arrayCopy(secret, (short)0, hashinput, (short)4, (short)secret.length);
        Util.arrayCopy(info, (short)0, hashinput, (short)(4+secret.length),
                                                        (short)info.length);

        // Number of keys required. Ceiling division to avoid underproducing.
        byte n = (byte) (len/hashlen);
        if (len%hashlen != 0){
            // For ceiling division, must increment n if there is a remainder.
            n++;
        }

        for (byte i = 0; i < n; i++) {
            hashinput[3] = (byte)(i+1);

            // If the last hash generates too much material to fit into the
            // final part of the output key array.
            if ((i == (short)(n-1)) && len%hashlen != 0) {
                // TODO: Try to avoid allocation here by using some shared temp
                // array.
                byte[] temp = new byte[32];
                hash(hashinput, (short)0, (short)hashinput.length, temp, (short)0);
                Util.arrayCopy(temp, (short)0, keys, (short)(i*hashlen), (short)(len%hashlen));
            } else {
                hash(hashinput, (short)0, (short)hashinput.length, keys, (short)(i*hashlen));
            }
        }
    }

    private void cmac(byte[] key, short key_offset, byte[] mac_input, byte[] sig, short sigOffset) {
        Signature aes_cmac = new AESCMAC128();
        AESKey mac_key = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);

        mac_key.setKey(key, (short)key_offset);

        aes_cmac.init(mac_key, Signature.MODE_SIGN);

        aes_cmac.sign(mac_input, (short)0, (short)mac_input.length, sig, sigOffset);
    }


    public void authenticate(APDU apdu) {
        // TODO: Reject request if cvc not issued.

        byte[] buffer = apdu.getBuffer();

        // Data section contains 8B ID followed by 77B public key.
        byte Lc = buffer[ISO7816.OFFSET_LC];
        // TODO: Lc should be 8+77=85B (or something). Check.

        // CDATA consists of 8B host ID, followed by

        byte[] id_h = new byte[8];
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, id_h, (short)0, (short)8);

        // P1 contains length of encoded public key.
        short keylen = Util.makeShort((byte)0x00, buffer[ISO7816.OFFSET_P1]);

        // TODO: Am I looking at the right part of pubkey?
        byte[] pubkey = new byte[keylen];
        Util.arrayCopy(buffer, (short)(ISO7816.OFFSET_CDATA+8), pubkey, (short)0, (short)keylen);

        validate_key(pubkey);
        byte[] z = get_secret(pubkey, apdu);

        if(buffer[ISO7816.OFFSET_P2] == 0x06) {
            return;
        }

        if(buffer[ISO7816.OFFSET_P2] == 0x01) {
            send(id_h, (short)0, (short)id_h.length, apdu);
            return;
        } else if (buffer[ISO7816.OFFSET_P2] == 0x02) {
            send(pubkey, (short)0, keylen, apdu);
            return;
        } else if (buffer[ISO7816.OFFSET_P2] == 0x03) {
            short ret_len = (short)(32 + cvc.length);
            byte[] ret_arr = new byte[ret_len];
            Util.arrayCopy(z, (short)0, ret_arr, (short)0, (short)16);
            Util.arrayCopy(cvc, (short)0, ret_arr, (short)32, (short)cvc.length);
            send(ret_arr, (short)0, ret_len, apdu);
            return;
        }

        // Return nonce, mac and cvc
        short return_len = (short)(16 + 16 + cvc.length);
        short nonce_offset = (short)0;
        short mac_offset = (short)16;
        short cvc_offset = (short)32;

        byte[] ret_buffer = apdu.getBuffer();
        short le = apdu.setOutgoing();
        if (le < return_len)
            ISOException.throwIt( ISO7816.SW_WRONG_LENGTH );
        apdu.setOutgoingLength(return_len);

        // Generate 16B nonce.
        RandomData rand = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        rand.generateData(ret_buffer, nonce_offset, (short)16);

        // Total length of required AES key material 5y where y is length of AES key in bytes.
        byte len = 5*16;

        // Some amount of contextual info to seed kdf.
        // TODO: Calculate info as id_c||id_h||truncate16(Q_h)||nonce
        byte[] info = new byte[16];
        byte[] keys = new byte[len];
        kdf(z, len, info, keys);



        // Parse out keys using offsets
        short k_crfm_offset = 0;

        short k_mac_offset = (short)16;
        short k_enc_offset = (short)32;
        short k_rmac_offset = (short)48;
        short next_z_offset = (short)64;

        // Zeroise array
        Util.arrayFillNonAtomic(z, (short)0, (short)z.length, (byte)0);

        // Initialise input to mac function

        // Length of input to cmac function
        short input_len = (short)(MESSAGE_STRING.length + id_card.length + id_h.length + 16);
        byte[] mac_input = new byte[input_len];

        short position = 0;
        Util.arrayCopy(MESSAGE_STRING, (short)0, mac_input, position, (short)MESSAGE_STRING.length);
        position += MESSAGE_STRING.length;
        Util.arrayCopy(id_card, (short)0, mac_input, position, (short)id_card.length);
        position += id_card.length;
        Util.arrayCopy(id_h, (short)0, mac_input, position, (short)id_h.length);
        position += id_h.length;

        // Only need leftmost 16 bytes of pubkey_h.
        Util.arrayCopy(pubkey, (short)0, mac_input, position, (short)16);

        // Generate cmac, placing output into return buffer.
        cmac(keys, k_crfm_offset, mac_input, ret_buffer, mac_offset);

        // Copy card's CVC into return buffer.
        Util.arrayCopy(cvc, (short)0, ret_buffer, cvc_offset, (short)cvc.length);

        apdu.sendBytes((short)0, return_len);

    }


    public void send(byte[] buf, short offset, short len, APDU apdu) {
        byte[] ret_buffer = apdu.getBuffer();

        short ret_len = apdu.setOutgoing();

        if (ret_len < len)
            ISOException.throwIt( ISO7816.SW_WRONG_LENGTH );
        apdu.setOutgoingLength(len);

        Util.arrayCopy(buf, offset, ret_buffer, (short)0, len);

        apdu.sendBytes((short)0, len);
    }


    public void init_keys_and_sign(APDU apdu) {
        short sig_len = 64;
        short key_len = 65;
        // Generate 256b EC key pair.
        ECPrivateKey p = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, (short)256, false);
        ECPublicKey q = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, (short)256, false);

        // Initialise key parameters to the parameters of SECP256R1 curve.
        p.setA(SECP256R1_A, (short)0, (short)SECP256R1_A.length);
        p.setB(SECP256R1_B, (short)0, (short)SECP256R1_B.length);
        p.setFieldFP(SECP256R1_P, (short)0, (short)SECP256R1_P.length);
        p.setG(SECP256R1_G, (short)0, (short)SECP256R1_G.length);
        p.setK(SECP256R1_H);
        p.setR(SECP256R1_N, (short)0, (short)SECP256R1_N.length);

        q.setA(SECP256R1_A, (short)0, (short)SECP256R1_A.length);
        q.setB(SECP256R1_B, (short)0, (short)SECP256R1_B.length);
        q.setFieldFP(SECP256R1_P, (short)0, (short)SECP256R1_P.length);
        q.setG(SECP256R1_G, (short)0, (short)SECP256R1_G.length);
        q.setK(SECP256R1_H);
        q.setR(SECP256R1_N, (short)0, (short)SECP256R1_N.length);


        // Create the KeyPair using the two individual uninitialised keys.
        kp = new KeyPair(q, p);

        // Generate values for the key pair.
        kp.genKeyPair();

        ECPublicKey pub = (ECPublicKey) kp.getPublic();


        if (pub.getSize() != 256) {
            // TODO: not the right type. Change.
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }

        // Temporary array containing the new public key and corresponding CVC signature.
        short total_len = (short)(key_len + sig_len);
        byte[] key_sig_array = JCSystem.makeTransientByteArray(total_len, JCSystem.CLEAR_ON_DESELECT);
        short keyBytes = 0;
        try {
            keyBytes = pub.getW(key_sig_array, (short)0);
        } catch(Exception e) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Should be 0x04 followed by 32B each for x and y coordinates.
        if (keyBytes != key_len) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        byte[] buffer = apdu.getBuffer();

        // Generate signature section for the CVC using the new private key.

        Signature signer = new ECDSA_SHA_256(m_ecc);
        signer.init(kp.getPrivate(), Signature.MODE_SIGN);

        byte issuer_id_len = buffer[ISO7816.OFFSET_P1];
        byte guid_len = (byte)(buffer[ISO7816.OFFSET_LC] - issuer_id_len);

        signer.update(buffer, ISO7816.OFFSET_CDATA, issuer_id_len);
        signer.update(buffer, (short)(ISO7816.OFFSET_CDATA + issuer_id_len), guid_len);

        short sigBytes = 0;

        // Outputs concatenation of r and s, 32B each.
        sigBytes = signer.sign(key_sig_array, (short)0, key_len, key_sig_array, key_len);
        if (sigBytes != sig_len) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        send(key_sig_array, (short)0, (short)(key_len + sig_len), apdu);
    }

    public void set_cvc(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
		short Lc = Util.makeShort((byte)0x00, buffer[ISO7816.OFFSET_LC]); // cvc length
        cvc = new byte[Lc];

		Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, cvc, (short)0, Lc);

        // Calculate ID from CVC.
        byte[] temp = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_DESELECT);
        hash(cvc, (short)0, (short)Lc, temp, (short)0);
        short id_bytes = 8;
        if (id_card == null) {
            id_card = new byte[id_bytes];
        }
        Util.arrayCopy(temp, (short)0, id_card, (short)0, (short)id_bytes);
    }

    public void process(APDU apdu) {
        // TODO: Move to setup
        if (m_ecc == null) {
            m_ecc = new ECConfig((short)512);
        }

        JCSystem.requestObjectDeletion();

        byte[] buffer = apdu.getBuffer();

		byte cla = buffer[ISO7816.OFFSET_CLA];
		byte ins = buffer[ISO7816.OFFSET_INS];

        if (cla != (byte)0x80) {
            // 0x80 means user-defined i.e. part of the protocol
            ISOException.throwIt(cla);
            return;
        }

        switch(ins) {
            // ins 0x20 is regular authentication request.
            case (byte)0x20:
                authenticate(apdu);
                break;
            case (byte)0x21:
                // Generate new key pair, return public key in APDU response.
                // TODO: Consider security implications of easily resetted keys.

                init_keys_and_sign(apdu);
                break;
            case (byte)0x22:
                // Accept and save CVC passed by issuer.
                // TODO: Consider implementing CVC construction on-card.
                set_cvc(apdu);
                break;

            default: ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }
    }
}
