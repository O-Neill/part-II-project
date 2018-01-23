package uk.ac.cam.bo271.applets.opacity_zkm_opt;

import javacard.security.KeyAgreement;
import javacard.security.MessageDigest;
import javacard.security.Signature;

/**
 *
* @author Petr Svenda
 */
public class ECPoint_Helper extends Base_Helper {
    // Selected constants missing from older JC API specs
    public static final byte KeyAgreement_ALG_EC_SVDP_DH_PLAIN = (byte) 3;
    public static final byte KeyAgreement_ALG_EC_SVDP_DH_PLAIN_XY = (byte) 6;
    public static final byte Signature_ALG_ECDSA_SHA_256 = (byte) 33;

    /**
     * I true, fast multiplication of ECPoints via KeyAgreement can be used Is
     * set automatically after successful allocation of required engines
     */
    public boolean FLAG_FAST_EC_MULT_VIA_KA = false;

    byte[] uncompressed_point_arr1;
    byte[] fnc_isEqual_hashArray;
    byte[] fnc_multiplication_resultArray;

    Signature    fnc_SignVerifyECDSA_signEngine;
    MessageDigest fnc_isEqual_hashEngine;

    public ECPoint_Helper(ResourceManager rm) {
        super(rm);

        FLAG_FAST_EC_MULT_VIA_KA = false; // set true only if succesfully allocated and tested below
        try {
            //fnc_multiplication_x_keyAgreement = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DHC, false);
            //fnc_SignVerifyECDSA_signEngine = Signature.getInstance(Signature.ALG_ECDSA_SHA, false);
            //fnc_multiplication_x_keyAgreement = KeyAgreement.getInstance(Consts.KeyAgreement_ALG_EC_SVDP_DH_PLAIN_XY, false);
            fnc_SignVerifyECDSA_signEngine = Signature.getInstance(Signature_ALG_ECDSA_SHA_256, false);
            FLAG_FAST_EC_MULT_VIA_KA = true;
        } catch (Exception ignored) {
        } // Discard any exception
    }

    void initialize() {
        // Important: assignment of helper BNs is made according to two criterions:
        // 1. Correctness: same BN must not be assigned to overlapping operations (guarded by lock/unlock)
        // 2. Memory tradeoff: we like to put as few BNs into RAM as possible. So most frequently used BNs for write should be in RAM
        //                      and at the same time we like to have as few BNs in RAM as possible.
        // So think twice before changing the assignments!

        fnc_multiplication_resultArray = rm.helper_BN_array1;

        fnc_isEqual_hashArray = rm.helper_hashArray;
        fnc_isEqual_hashEngine = rm.hashEngine;

        uncompressed_point_arr1 = rm.helper_uncompressed_point_arr1;

    }

}
