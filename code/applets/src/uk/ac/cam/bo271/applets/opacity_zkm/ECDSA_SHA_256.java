package uk.ac.cam.bo271.applets.opacity_zkm;

import javacard.security.Signature;
import javacard.security.Key;
import javacard.security.ECPrivateKey;
import javacard.security.MessageDigest;
import javacard.framework.JCSystem;
import javacard.security.RandomData;
import javacard.framework.Util;

import javacardx.framework.tlv.*;
import javacard.framework.ISOException;

public class ECDSA_SHA_256 extends Signature {
    private static ECConfig m_ecc;

    private static byte ALG_CODE = 33; // Algorithm code used in JC 3.x
    private static short OUTPUT_LEN = 70; // TODO: Check

    private ECPrivateKey ecdsa_key;

    private MessageDigest sha256;

    public ECDSA_SHA_256() {

    }

    public short getLength() {
        return OUTPUT_LEN;
    }

    public byte getAlgorithm() {
        return ALG_CODE;
    }

    public void update(byte[] inBuff, short inOffset, short inLength) {
        sha256.update(inBuff, inOffset, inLength);
    }

    public void init(Key theKey, byte theMode) {
        // TODO Possibly should refresh object anyway...
        if (sha256 == null) {
            sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        }
        ecdsa_key = (ECPrivateKey) theKey;
    }

    public void init(Key theKey, byte theMode, byte[] bArray, short bOff, short bLen) {
        // This implementation does not require additional information.
        init(theKey, theMode);
    }


    // Generate random number in the range [1, order-1]
    private byte[] randGenInRange(byte[] order, short len) {
        byte[] random_data = JCSystem.makeTransientByteArray(len, JCSystem.CLEAR_ON_DESELECT);
        RandomData rand = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

        while(true) {
            rand.generateData(random_data, (short)0, len);

            // Deal with extraordinary edge case that 0 is generated.
            boolean positive = false;
            for (short i = 0; i < len; i++) {
                if (random_data[i] > 0) {
                    positive = true;
                    break;
                }
            }

            // Only return if random data is less than the order. Else retry.
            // NOTE: Arrays are big-endian.
            if (positive) {
                for (short i = 0; i < len; i++) {
                    if (random_data[i] < order[i]) {
                        return random_data;
                    } else if (random_data[i] > order[i]) {
                        break;
                    }
                }
            }
        }
    }

    // When this returns, k contains its modular inverse.
    public void mod_inv(Bignat k, Bignat mod, Bignat_Helper bnh) {
        Bignat n = new Bignat(k.length(), JCSystem.CLEAR_ON_RESET, bnh);
        n.copy(mod);

        // If n is one, no solution. Return 0.
        byte[] n_arr = n.as_byte_array();
        boolean is_one = false;
        if (n_arr[(short)(n.length()-1)] == 0x01) {
            is_one = true;
            for (short i = 0; i < (short)(n.length()-1); i++) {
                if (n_arr[i] != 0) {
                    is_one = false;
                    k.zero();
                    return;
                }
            }
        }
        /*

        Bignat q = new Bignat(k.length(), JCSystem.CLEAR_ON_RESET, bnh);
        Bignat t = new Bignat(k.length(), JCSystem.CLEAR_ON_RESET, bnh);
        Bignat x0 = new Bignat(k.length(), JCSystem.CLEAR_ON_RESET, bnh);
        x0.zero();

        Bignat n0 = new Bignat(k.length(), JCSystem.CLEAR_ON_RESET, bnh);
        n0.copy(n);

        // Initialise x1 = 1
        Bignat x1 = new Bignat(k.length(), JCSystem.CLEAR_ON_RESET, bnh);
        x1.zero();
        x1.increment_one();

        Bignat zero = new Bignat(k.length(), JCSystem.CLEAR_ON_RESET, bnh);
        zero.zero();

        // Longer length needed?
        Bignat intermediate = new Bignat((short)(2 * k.length()), JCSystem.CLEAR_ON_RESET, bnh);

        // while k > 1
        while(Bignat_Helper.ONE.smaller(k))
        {
            // q is quotient
            q.copy(k);
            q.divide(n);

            t.copy(n);

            // m is remainder now, process
            // same as Euclid's algo
            k.mod(n);
            n.copy(k);
            k.copy(t);

            t.copy(x0);

            // x0 = x1 - q * x0;
            intermediate.mult(q, x0);

            x1.copy(t);
        }

        // Make x1 positive
        if (x1.smaller(zero))
            x1.add(n0);

        // Return the value currently stored in x1.
        k.copy(x1);
        */
    }

    public short sign(byte[] inBuff, short inOffset, short inLength, byte[] sigBuff, short sigOffset) {

        // TODO: Lots of arrays created. See if this can be reduced.
        // Unsure if this is correct use of the library.
        // TODO: maxECLength could be reduced to 256

        if (m_ecc == null) {
            m_ecc = new ECConfig((short)512);
        }

        // Locking had to be disabled because there appears to be a bug in the
        // library. This function worked the first time, but the second time
        // it failed because the lock object had somehow been lost from the
        // locking list.
        m_ecc.bnh.rm.locker.setLockingActive(false);

        // TODO: Could make more efficient by using sigBuff as temp hash buffer.
        byte[] e = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_RESET);
        sha256.doFinal(inBuff, inOffset, inLength, e, (short)0);


        byte[] order = JCSystem.makeTransientByteArray((short)64, JCSystem.CLEAR_ON_RESET);
        short order_len = ecdsa_key.getR(order, (short)0);
        // TODO: Verify order_len == 32 (or deal with general case)

        // Resize order array.
        byte[] order_cpy = JCSystem.makeTransientByteArray(order_len, JCSystem.CLEAR_ON_RESET);
        Util.arrayCopy(order, (short)0, order_cpy, (short)0, order_len);
        Bignat n = new Bignat(order_cpy, m_ecc.bnh);

        // z is <order_len> leftmost bytes of e.

        // Calculate point (x,y) = k*G using Bignat. y coordinate not needed.
        byte[] G = JCSystem.makeTransientByteArray((short)65, JCSystem.CLEAR_ON_RESET);
        ecdsa_key.getG(G, (short)0);
        byte[] G_x_arr = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_RESET);
        Util.arrayCopy(G, (short)1, G_x_arr, (short)0, (short)32);

        // Generate random nonce k in the range [1, n-1]
        byte[] random_k = randGenInRange(order, order_len);
        Bignat k = new Bignat(random_k, m_ecc.bnh);

        // Initialise results with sufficient space to store multiplication results.
        // Find the curve point (x,y) = k * G
        Bignat G_x = new Bignat(G_x_arr, m_ecc.bnh);
        Bignat x = new Bignat(order_len, JCSystem.CLEAR_ON_RESET, m_ecc.bnh);


        x.mod_mult(k, G_x, n);
        if (k.is_zero()) {
            ISOException.throwIt((short)0x0001);
        }
        if (G_x.is_zero()) {
            ISOException.throwIt((short)0x0002);
        }
        if (x.is_zero()) {
            ISOException.throwIt((short)0x0003);
        }

        // r = x mod n where n is order.
        x.mod(n);
        // x now contains r
        Bignat r = x;

        // TODO: Handle r=0 as in algorithm
        byte[] d_arr = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_DESELECT);
        short key_len = ecdsa_key.getS(d_arr, (short)0);
        if (key_len != 32) {
            ISOException.throwIt((short)0x4300);
        }
        Bignat d = new Bignat(d_arr, m_ecc.bnh);


        byte[] z_arr = JCSystem.makeTransientByteArray(order_len, JCSystem.CLEAR_ON_DESELECT);
        Util.arrayCopy(e, (short)0, z_arr, (short)0, order_len);
        Bignat z = new Bignat(z_arr, m_ecc.bnh);

        // Get inverse of k modulo n
        mod_inv(k, n, m_ecc.bnh);

        Bignat s = new Bignat(order_len, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, m_ecc.bnh);

        // s = (z + r*d) * k^-1
        s.mod_mult(r, d, n);
        s.mod_add(z, n);
        s.mod_mult(k, s, n);
        // TODO: Deal with extreme case s=0

        // Return (r,s).
        // Should technically be in ANS.1 format. Could do later.
        // TODO: Ensure byte length of r and s is 32
        Util.arrayCopy(r.as_byte_array(), (short)0, sigBuff, sigOffset, (short)32);
        Util.arrayCopy(s.as_byte_array(), (short)0, sigBuff, (short)(sigOffset+32), (short)32);
        return (short)(s.length() + r.length());
    }

    public boolean verify(byte[] inBuff, short inOffset, short inLength, byte[] sigBuff, short sigOffset, short sigLength) {
        // TODO implement
        return true;
    }


}