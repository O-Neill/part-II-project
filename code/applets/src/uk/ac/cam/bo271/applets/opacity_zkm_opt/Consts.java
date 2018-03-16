package uk.ac.cam.bo271.applets.opacity_zkm_opt;
import javacard.framework.ISO7816;

public class Consts {
    // Use persistent binding.
    public static final byte PB = (byte)0x01;

    // Don't use persistent binding.
    public static final byte NO_PB = (byte)0x00;

    // Reset persistent binding entry for this host.
    public static final byte PB_INIT = (byte)0x02;

    // Host requests the encrypted GUID in the response.
    public static final byte RET_GUID = (byte)0x10;

    // Host expects a single session key.
    public static final byte ONE_SK = (byte)0x20;

    // Use these to make program easier to understand and modify:
    public static final short ECDH_LEN = (short)32;
    public static final short ID_LEN = (short)8;
    public static final short CMAC_LEN = (short)16;
    public static final short NONCE_LEN = (short)16;
    public static final short SESSIONKEY_LEN = (short)16;
    public static final short PUBKEY_LEN = (short)65;

    public static final short HASHFUN_OUTPUT_LEN = (short)32;

    public static final short KDF_LEN_KEYS = (short)(4*SESSIONKEY_LEN + ECDH_LEN);
    public static final short KDF_INFO_LEN = (short)(2 * ID_LEN + 16 + NONCE_LEN);
    public static final short KDF_HASH_INPUT_LEN = (short)(4 + ECDH_LEN + KDF_INFO_LEN);
    public static final short K_CRFM_OFFSET = 0;
    public static final short K_MAC_OFFSET = 1*SESSIONKEY_LEN;
    public static final short K_ENC_OFFSET = 2*SESSIONKEY_LEN;
    public static final short K_RMAC_OFFSET = 3*SESSIONKEY_LEN;
    public static final short NEXT_Z_OFFSET = 4*SESSIONKEY_LEN;

    // 6B message string forming the start of the CMAC input as per NIST 800-56A.
    // Represents "KC_1_V" meaning party V provides the tag in unilateral key confirmation.
    public static final byte[] MSG_STRING = {(byte)75, (byte)67, (byte)95,
                                            (byte)49, (byte)95, (byte)86};
    public static final short MSG_STRING_LEN = (short)6;
    public static final short CMAC_INPUT_LEN = (short)(MSG_STRING_LEN + 2*ID_LEN + 16);

    // Offsets for authenticate APDU
    public static final short AUTH_OFFSET_ID_H = (short)(ISO7816.OFFSET_CDATA);
    public static final short AUTH_OFFSET_PUBKEY = (short)(AUTH_OFFSET_ID_H + ID_LEN);
    public static final short AUTH_OFFSET_CB_H = (short)(AUTH_OFFSET_PUBKEY + PUBKEY_LEN);

    // Most that can be returned is control byte, nonce, mac, enc_guid, and cvc.
    public static final short MAX_RETURN_LEN = (short)(1 + NONCE_LEN + CMAC_LEN + 16 + 200);



    // Workspace array constants
    public static final short WORKSPACE_LEN = (short)(ID_LEN + NONCE_LEN + KDF_HASH_INPUT_LEN + HASHFUN_OUTPUT_LEN + KDF_LEN_KEYS);
    public static final short OFFSET_ID_H = (short)0;
    public static final short OFFSET_NONCE = (short)(OFFSET_ID_H + ID_LEN);
    // Offsets of z and kdf info carefully chosen so no copy is necessary.
    public static final short OFFSET_HASHINPUT = (short)(OFFSET_NONCE + NONCE_LEN);
    public static final short OFFSET_Z = (short)(OFFSET_HASHINPUT + 4);
    public static final short OFFSET_KDF_INFO = (short)(OFFSET_Z + ECDH_LEN);
    public static final short OFFSET_HASH_AUX = (short)(OFFSET_HASHINPUT + KDF_HASH_INPUT_LEN);
    public static final short OFFSET_KEYS = (short)(OFFSET_HASH_AUX + HASHFUN_OUTPUT_LEN);
    // Hashinput and hash aux no longer needed, so reuse of space is safe.
    // Nonce and CMAC are kept adjacent so they can be copied to output buffer
    // during the same copy.
    public static final short OFFSET_CMAC = OFFSET_HASHINPUT;
    public static final short OFFSET_CMAC_INPUT = (short)(OFFSET_CMAC + CMAC_LEN);
}
