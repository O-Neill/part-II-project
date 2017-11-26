package uk.ac.cam.bo271.applets.opacity_zkm;

import javacard.framework.*;
import javacard.security.MessageDigest;
import javacard.security.KeyBuilder;
import javacard.security.PublicKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyPair;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacard.security.AESKey;
// TODO: Consider what happens if deselect at any point.

public class Opacity extends Applet {
    private static byte[] cvc;
    private static byte[] id_card;

    // TODO: initialise.
    private static KeyPair kp;

    public static void install(byte[] bArray, short bOffset, byte bLength) {

    }

    // NOTE: Could be made more efficient if it reads relevant part directly
    // from overall array (rather than copying into separate array).
    private void hash(byte[] input, short inOffset, short len, byte[] output, short outOffset) {
        // Initialise SHA-256 digest, don't allow sharing with other applets.
        MessageDigest hash = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        hash.doFinal(input, inOffset, len, output, outOffset);
    }

    // Verify input key belongs to EC domain.
    private void validate_key(byte[] key) {
        /*ECPublicKey pubkey = (ECPublicKey) KeyBuilder.buildKey(
                        KeyBuilder.TYPE_EC_FP_PUBLIC,
                        (short)0x0100,
                        false);*/
        // Not really sure how to verify key belongs to EC domain.
    }

    private byte[] get_secret(byte[] pubkey_host) {
        // NOTE: Key agreement with cofactor multiplication. Is this what I want?
        KeyAgreement dh = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DHC, false);
        dh.init(kp.getPrivate());



        // Correct? No clue if I should get rid of the leading stuff.
        short size = 77;

        byte temp[] = new byte[100];

        // Throws CryptoException if pubkey formatted wrong.
        short len = dh.generateSecret(pubkey_host, (byte) 0, size, temp, (byte) 0);

        byte[] output = new byte[len];
        Util.arrayCopy(temp, (byte)0, output, (short)0, len);
        return output;
    }

    // Outputs key material in 'keys' array.
    public void kdf(byte[] secret, byte len, byte[] info, byte[] keys) {
        byte hashlen = 32;

        short hashinputlen = (short)(4 + secret.length + info.length);

        // NOTE: Is this overwritten by hash function?
        // NOTE: Initialised to 0?
        byte[] hashinput = new byte[hashinputlen];
        Util.arrayCopy(secret, (short)0, hashinput, (short)4, (short)secret.length);
        Util.arrayCopy(info, (short)0, hashinput, (short)(4+secret.length),
                                                        (short)info.length);

        // TODO: Deal with bizarre case of n>256
        // Number of keys required. Ceiling division to avoid underproducing.
        byte n = (byte) (len/hashlen);
        if (len%hashlen != 0){
            // For ceiling division, must increment n if there is a remainder.
            n++;
        }
        for (byte i = 0; i < n; i++) {
            hashinput[3] = (byte)(i+1);
            hash(hashinput, (short)0, (short)hashinput.length, keys, (short)(i*hashlen));
        }
    }

    private void cmac(byte[] key, short key_offset, byte[] mac_input, byte[] sig, short sigOffset) {

        Signature aes_cmac = new AESCMAC128();
        AESKey mac_key = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        mac_key.setKey(key, (short)key_offset);
        aes_cmac.init(mac_key, Signature.MODE_SIGN);

        aes_cmac.sign(mac_input, (short)0, (short)mac_input.length, sig, sigOffset);
    }

// TODO: Make more efficient by not copying arrays.
    public void authenticate(APDU apdu) {
        // TODO: Reject request if keys not issued.

        byte[] buffer = apdu.getBuffer();
        // Data section contains 8B ID followed by 77B public key.
        byte Lc = buffer[ISO7816.OFFSET_LC];
        // TODO: Lc should be 8+77=85B (or something). Check.

        // CDATA consists of 8B host ID, followed by

        byte[] id_h = new byte[8];
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, id_h, (short)0, (short)8);

        // TODO: Am I looking at the right part of pubkey?
        byte[] pubkey = new byte[77];
        Util.arrayCopy(buffer, (short)(ISO7816.OFFSET_CDATA+8), pubkey, (short)0, (short)77);

        validate_key(pubkey);
        byte[] z = get_secret(pubkey);

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
        // TODO: Initialise ver to byte representation of "KC_1_V"
        byte[] ver = new byte[0];

        // Length of input to cmac function
        short input_len = (short)(ver.length + id_card.length + id_h.length + 16);
        byte[] mac_input = new byte[input_len];

        short position = 0;
        Util.arrayCopy(ver, (short)0, mac_input, position, (short)ver.length);
        position += ver.length;
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

    public void issue(APDU apdu) {
        // Run as atomic transaction.
        JCSystem.beginTransaction();

        // TODO: key issuing or whatever. (Or should this be done by APDU?
        // Although that may not be secure)
        // i.e. issue CVC. Also compute ID from CVC.
        // TODO: Calculate ID from CVC
        JCSystem.commitTransaction();
    }

    public void process(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

		byte cla = buffer[ISO7816.OFFSET_CLA];
		byte ins = buffer[ISO7816.OFFSET_INS];
        switch(cla) {
            // ISO7816-4 command, typically seen due to SELECT command.
            case (byte)0x00:
                return;

            // 0x80 means user-defined i.e. part of the protocol.
            case (byte)0x80:
                break;
        }

        switch(ins) {
            // ins 0x20 is regular authentication request.
            case (byte)0x20:
                authenticate(apdu);
                break;
            case (byte)0x21:
                issue(apdu);
                break;

            default: ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }
    }
}
