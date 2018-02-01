package uk.ac.cam.bo271.applets.opacity_zkm;

import javacard.framework.*;
import javacard.security.MessageDigest;
import javacard.security.KeyBuilder;
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


    private byte[] get_secret(byte[] pubkey_host, APDU apdu) {
        // NOTE: Key agreement with cofactor multiplication. Is this what I want?
        KeyAgreement dh = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);

        // TODO: Correct? or provide key in another form?
        dh.init(kp.getPrivate());

        // TODO: What's the smallest array I can use?
        byte temp[] = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_DESELECT);

        // Throws CryptoException if pubkey formatted wrong.
        short len = 0;


        try {
            len = dh.generateSecret(pubkey_host, (short)0, (short)pubkey_host.length, temp, (byte)0);
        } catch (CryptoException e) {
            if (e.getReason() != 0x01) {
                ISOException.throwIt((short)0x3638);
                ISOException.throwIt((short)(e.getReason() + 0x1100));
            } else {
                ISOException.throwIt((short)0x3637);
                return null;
            }
        }


        byte[] output = new byte[len];
        Util.arrayCopy(temp, (byte)0, output, (short)0, len);
        return output;

    }

    // Outputs key material in 'keys' array.
    public void kdf(byte[] secret, short len, byte[] info, byte[] keys, short outOffset, APDU apdu) {
        short hashlen = 32;

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
                Util.arrayCopy(temp, (short)0, keys, (short)(outOffset + i*hashlen), (short)(len%hashlen));
            } else {

                byte[] buffer = apdu.getBuffer();
                if (i == 0 && buffer[ISO7816.OFFSET_P2] == 0x07) {
                    Util.arrayCopy(hashinput, (short)0, keys, outOffset, (short)hashinput.length);
                    hash(hashinput, (short)0, (short)hashinput.length, keys, (short)(outOffset + hashinput.length + 8));
                    return;
                }

                hash(hashinput, (short)0, (short)hashinput.length, keys, (short)(outOffset + i*hashlen));

            }
        }
    }

    private void cmac(byte[] key, short key_offset, byte[] mac_input, byte[] sig, short sigOffset) {
        Signature aes_cmac = new AESCMAC128();
        AESKey mac_key = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);

        mac_key.setKey(key, key_offset);

        try {
            aes_cmac.init(mac_key, Signature.MODE_SIGN);
        } catch (CryptoException e) {
            ISOException.throwIt(Util.makeShort((byte)0x52, (byte)e.getReason()));
        }

        try {
            aes_cmac.sign(mac_input, (short)0, (short)mac_input.length, sig, sigOffset);
        } catch (CryptoException e) {
            ISOException.throwIt(Util.makeShort((byte)0x53, (byte)e.getReason()));
        }
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
        Util.arrayCopy(buffer, (short)(ISO7816.OFFSET_CDATA+8), pubkey, (short)0, keylen);

        validate_key(pubkey);
        byte[] z = get_secret(pubkey, apdu);
        if (z == null) {
            return;
        }

        // Return nonce, mac and cvc
        short return_len = (short)(16 + 16 + cvc.length);
        short nonce_offset = (short)0;
        short mac_offset = (short)16;
        short cvc_offset = (short)32;

        byte[] ret_buffer = new byte[return_len];

        // Generate 16B nonce.
        RandomData rand = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        rand.generateData(ret_buffer, nonce_offset, (short)16);

        // Total length of required AES key material 5y where y is length of AES key in bytes.
        short len = (short)(4*16 + 64);

        // Some amount of contextual info to seed kdf.
        // Calculate info as id_c||id_h||truncate16(Q_h)||nonce
        short info_len = (short)(id_h.length + id_card.length + 16 + 16);
        byte[] info = new byte[info_len];
        short offset = 0;
        Util.arrayCopy(id_card, (short)0, info, offset, (short)id_card.length);
        offset += id_card.length;
        Util.arrayCopy(id_h, (short)0, info, offset, (short)id_h.length);
        offset += id_h.length;
        Util.arrayCopy(pubkey, (short)0, info, offset, (short)16);
        offset += 16;
        Util.arrayCopy(ret_buffer, nonce_offset, info, offset, (short)16);


        byte[] keys = new byte[len];
        kdf(z, len, info, keys, (short)0, apdu);


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

        JCSystem.requestObjectDeletion();
        // Generate cmac, placing output into return buffer.
        cmac(keys, k_crfm_offset, mac_input, ret_buffer, mac_offset);

        // Copy card's CVC into return buffer.
        Util.arrayCopy(cvc, (short)0, ret_buffer, cvc_offset, (short)cvc.length);

        send(ret_buffer, (short)0, return_len, apdu);
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
        short sig_len = 72;
        short key_len = 65;
        // Generate 256b EC key pair.
        ECPrivateKey p = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, (short)256, false);
        ECPublicKey q = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, (short)256, false);

        // Initialise key parameters to the parameters of SECP256R1 curve.
        p.setA(SecP256r1.a, (short)0, (short)SecP256r1.a.length);
        p.setB(SecP256r1.b, (short)0, (short)SecP256r1.b.length);
        p.setFieldFP(SecP256r1.p, (short)0, (short)SecP256r1.p.length);
        p.setG(SecP256r1.G, (short)0, (short)SecP256r1.G.length);
        p.setK((short)0x01);
        p.setR(SecP256r1.r, (short)0, (short)SecP256r1.r.length);

        q.setA(SecP256r1.a, (short)0, (short)SecP256r1.a.length);
        q.setB(SecP256r1.b, (short)0, (short)SecP256r1.b.length);
        q.setFieldFP(SecP256r1.p, (short)0, (short)SecP256r1.p.length);
        q.setG(SecP256r1.G, (short)0, (short)SecP256r1.G.length);
        q.setK((short)0x01);
        q.setR(SecP256r1.r, (short)0, (short)SecP256r1.r.length);


        // Create the KeyPair using the two individual uninitialised keys.
        kp = new KeyPair(q, p);

        // Generate values for the key pair.
        kp.genKeyPair();

        if (q.getSize() != 256) {
            // TODO: not the right type. Change.
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }

        // Temporary array containing the new public key and corresponding CVC signature.
        short total_len = (short)(key_len + sig_len);
        byte[] key_sig_array = JCSystem.makeTransientByteArray(total_len, JCSystem.CLEAR_ON_DESELECT);
        short keyBytes = 0;
        try {
            keyBytes = q.getW(key_sig_array, (short)0);
        } catch(Exception e) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Should be 0x04 followed by 32B each for x and y coordinates.
        if (keyBytes != key_len) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        byte[] buffer = apdu.getBuffer();



        // Generate signature section for the CVC using the new private key.

        // Calling library version. Try to get my own working.
        //Signature signer = new ECDSA_SHA_256(m_ecc);
        Signature signer = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        signer.init(kp.getPrivate(), Signature.MODE_SIGN);

        byte issuer_id_len = buffer[ISO7816.OFFSET_P1];
        byte guid_len = (byte)(buffer[ISO7816.OFFSET_LC] - issuer_id_len);

        signer.update(buffer, ISO7816.OFFSET_CDATA, issuer_id_len);
        signer.update(buffer, (short)(ISO7816.OFFSET_CDATA + issuer_id_len), guid_len);

        short sigBytes = 0;

        // Outputs concatenation of r and s, 32B each.
        sigBytes = signer.sign(key_sig_array, (short)0, key_len, key_sig_array, key_len);

        if (sigBytes != sig_len) {
            //ISOException.throwIt(sigBytes);
        }

        send(key_sig_array, (short)0, (short)(key_len + sigBytes), apdu);
    }

    public void set_cvc(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
		short Lc = Util.makeShort((byte)0x00, buffer[ISO7816.OFFSET_LC]); // cvc length
        cvc = new byte[Lc];

		Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, cvc, (short)0, Lc);

        // Calculate ID from CVC.
        byte[] temp = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_DESELECT);
        hash(cvc, (short)0, Lc, temp, (short)0);
        short id_bytes = 8;
        if (id_card == null) {
            id_card = new byte[id_bytes];
        }
        Util.arrayCopy(temp, (short)0, id_card, (short)0, id_bytes);
    }


    public void process(APDU apdu) {
        //BignatStore.apdu = apdu;

        // TODO: Move to install
        if (m_ecc == null) {
            // TODO: Should it be 256?
            m_ecc = new ECConfig((short)512);
            m_ecc.bnh.rm.locker.setLockingActive(false);
            BignatStore.init(m_ecc.bnh);
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


        try {
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

                case (byte)0x23:
                    //AESCMAC128.test(apdu);
                    break;

                case (byte)0x24:
                    // ECPoint testing
                    break;

                default: ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
            }
        } catch (ArithmeticException e) {
            ISOException.throwIt(Util.makeShort((byte)0x04, (byte)0x00));
        } catch (ArrayStoreException e) {
            ISOException.throwIt(Util.makeShort((byte)0x05, (byte)0x00));
        } catch (ClassCastException e) {
            ISOException.throwIt(Util.makeShort((byte)0x06, (byte)0x00));
        } catch (IndexOutOfBoundsException e) {
            ISOException.throwIt(Util.makeShort((byte)0x07, (byte)0x00));
        } catch (NegativeArraySizeException e) {
            ISOException.throwIt(Util.makeShort((byte)0x08, (byte)0x00));
        } catch (NullPointerException e) {
            ISOException.throwIt(Util.makeShort((byte)0x09, (byte)0x00));
        } catch (SecurityException e) {
            ISOException.throwIt(Util.makeShort((byte)0x0A, (byte)0x00));
        } catch (APDUException e) {
            ISOException.throwIt(Util.makeShort((byte)0x0B, (byte)e.getReason()));
        } catch (CryptoException e) {
            ISOException.throwIt(Util.makeShort((byte)0x0C, (byte)e.getReason()));
        } catch (ISOException e) {
            ISOException.throwIt(Util.makeShort((byte)0x0D, (byte)e.getReason()));
        } catch (PINException e) {
            ISOException.throwIt(Util.makeShort((byte)0x0E, (byte)e.getReason()));
        } catch (SystemException e) {
            ISOException.throwIt(Util.makeShort((byte)0x0F, (byte)e.getReason()));
        } catch (TransactionException e) {
            ISOException.throwIt(Util.makeShort((byte)0x10, (byte)e.getReason()));
        } catch (CardRuntimeException e) {
            ISOException.throwIt(Util.makeShort((byte)0x11, (byte)e.getReason()));
        } catch (Exception e) {
            ISOException.throwIt(Util.makeShort((byte)0xFF, (byte)0x00));
        }
    }
}
