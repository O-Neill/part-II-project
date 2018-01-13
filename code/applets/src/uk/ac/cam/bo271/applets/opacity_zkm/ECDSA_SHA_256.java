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

    public ECDSA_SHA_256(ECConfig ecc) {
        m_ecc = ecc;
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
            sha256.reset();
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



    public short sign(byte[] inBuff, short inOffset, short inLength, byte[] sigBuff, short sigOffset) {

        // TODO: Lots of arrays created. See if this can be reduced.
        // Unsure if this is correct use of the library.
        // TODO: maxECLength could be reduced to 256
        // TODO: Check SigBuff can accommodate 64B
        // TODO: Use sigBuff as intermediate buffer to reduce memory usage.

        // Locking had to be disabled because there appears to be a bug in the
        // library. This function worked the first time, but the second time
        // it failed because the lock object had somehow been lost from the
        // locking list.

        // Step 0: Get order value n.
        byte[] order = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_RESET);
        short order_len = ecdsa_key.getR(order, (short)0);
        // Verify order_len is 32B
        if (order_len != 32) {
            ISOException.throwIt(Util.makeShort((byte)0x34, (byte)order_len));
        }

        // Step 1: e = HASH(msg)
        // TODO: Could make more efficient by using sigBuff as temp hash buffer.
        byte[] e = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_RESET);
        sha256.doFinal(inBuff, inOffset, inLength, e, (short)0);

        if (order_len != (short)e.length) {
            ISOException.throwIt((short)e.length);
        }
        // Step 2: Z is order_len leftmost bytes of e.
        // But order_len = e.length already (both 32B) so no new array
        // allocation necessary.
        byte[] z_arr = e;
        // Step 3: Select cryptographically secure random integer k from
        // [1, n-1].
        byte[] random_k = randGenInRange(order, order_len);
        Bignat k = new Bignat(random_k, m_ecc.bnh);

        // Step 4: Calculate point (x,y) = h*k*G. y coordinate not needed. h=1.
        // Have to pass array with 65 free bytes
        // TODO: Reuse G later.
        byte[] G = JCSystem.makeTransientByteArray((short)65, JCSystem.CLEAR_ON_RESET);
        ecdsa_key.getG(G, (short)0);

        // First byte is a 0x04 marker value, not part of the coordinates.
        // Copy the 32B X coordinate.
        byte[] G_x_arr = JCSystem.makeTransientByteArray(order_len, JCSystem.CLEAR_ON_RESET);
        Util.arrayCopy(G, (short)1, G_x_arr, (short)0, order_len);

        // Find the curve point (x,y) = k * G
        Bignat G_x = new Bignat(G_x_arr, m_ecc.bnh);
        // TODO: Unused Bignat or array I can use here?
        Bignat x = new Bignat(order_len, JCSystem.CLEAR_ON_RESET, m_ecc.bnh);

        // Create order Bignat.
        Bignat n = new Bignat(order, m_ecc.bnh);

        x.mod_mult(k, G_x, n);

        // Step 5: r = x mod n
        Bignat r = x;

        // TODO: Handle r=0 as in algorithm

        // Step 6: Calculate s.
        byte[] d_arr = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_DESELECT);
        short key_len = ecdsa_key.getS(d_arr, (short)0);
        if (key_len != 32) {
            ISOException.throwIt((short)0x4300);
        }
        Bignat d = new Bignat(d_arr, m_ecc.bnh);

        // Get inverse of k modulo n
        ArithmeticFuncs.mod_inv(k, n, m_ecc.bnh, null);

        Bignat s = new Bignat(order_len, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, m_ecc.bnh);

        // s = (z + r*d) * k^-1
        s.mod_mult(r, d, n);

        Bignat z = new Bignat(z_arr, m_ecc.bnh);
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
