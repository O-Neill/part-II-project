package uk.ac.cam.bo271.applets.opacity_zkm_opt;

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
}
