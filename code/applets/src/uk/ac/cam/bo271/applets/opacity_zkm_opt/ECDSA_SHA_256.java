package uk.ac.cam.bo271.applets.opacity_zkm_opt;

import javacard.security.Signature;
import javacard.security.Key;
import javacard.security.ECPrivateKey;
import javacard.security.MessageDigest;
import javacard.framework.JCSystem;
import javacard.security.RandomData;
import javacard.framework.Util;

import javacard.framework.*;

public class ECDSA_SHA_256 extends Signature {
    ECConfig ecc;

    private static byte ALG_CODE = 33; // Algorithm code used in JC 3.x
    private static short OUTPUT_LEN = 70; // TODO: Check

    private ECPrivateKey ecdsa_key;

    private MessageDigest sha256;

    public short signPreComputedHash(byte[] hashBuff, short hashOff, short hashLength, byte[] sigBuff, short sigOffset) {
        // TODO
        return 0;
    }

    public void setInitialDigest(byte[] initialDigestBuf, short initialDigestOffset, short initialDigestLength, byte[] digestedMsgLenBuf, short digestedMsgLenOffset, short digestedMsgLenLength) {
        // TODO
    }

    public ECDSA_SHA_256(ECConfig m_ecc) {
        this.ecc = m_ecc;
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

        if ((short)e.length != (short)32) {
            ISOException.throwIt((short)0x4301);
        }

        // Step 2: Z is order_len leftmost bytes of e.
        // But order_len = e.length already (both 32B) so no new array
        // allocation necessary.
        byte[] z_arr = e;


        // Step 3: Select cryptographically secure random integer k from
        // [1, n-1].
        byte[] random_k = randGenInRange(order, order_len);
        Bignat k = BignatStore.temp_val_1;
        k.from_byte_array(random_k);


        // Step 4: Calculate point (x,y) = h*k*G. y coordinate not needed. h=1.
        // Have to pass array with 65 free bytes
        // TODO: Reuse G later.
        byte[] G = new byte[65];
        ecdsa_key.getG(G, (short)0);

        ECCurve curve = new ECCurve(false, SecP256r1.p, SecP256r1.a, SecP256r1.b, SecP256r1.G, SecP256r1.r);
        ECPoint G_point = new ECPoint(curve, ecc.ech);
        G_point.setW(G, (short)0, (short)65);


        // Carry out the EC point multiplication and get the 32B X coordinate.
        ArithmeticFuncs.point_mult(G_point, k, BignatStore.temp_val_2, BignatStore.temp_val_3, BignatStore.temp_val_4, BignatStore.temp_val_5, BignatStore.temp_val_6, BignatStore.temp_val_7, ecc);
        ECPoint sig_point = G_point;
/*
        byte[] x_arr = new byte[32];
        sig_point.getX(x_arr, (short)0);


        // TODO: Aside: Before other Bignats are assigned but after k has been used,
        // initiate mod_inv call which uses Bignats.

        // Find the curve point (x,y) = k * G
        Bignat x = BignatStore.temp_val_2;
        x.from_byte_array(x_arr);

        // Step 5: Calculate r = x mod n.
        // TODO: Unused Bignat or array I can use here?
        // Create order Bignat.
        Bignat n = BignatStore.temp_val_3;
        n.from_byte_array(order);
        Bignat r = x;
        r.mod(n);
        Util.arrayCopy(r.as_byte_array(), (short)0, sigBuff, sigOffset, (short)32);

        // Step 6: Calculate s = k^{-1}(z + rd).
        byte[] d_arr = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_DESELECT);
        short key_len = ecdsa_key.getS(d_arr, (short)0);

        Bignat d = BignatStore.temp_val_4;
        d.from_byte_array(d_arr);

        // s = (z + r*d) * k^-1
        r.mod_mult(r, d, n);
        Bignat temp = d;

        // Get inverse of k modulo n
        ArithmeticFuncs.mod_inv(k, n, temp, BignatStore.temp_val_5, BignatStore.temp_val_6, BignatStore.temp_val_7, BignatStore.temp_val_8, null);

        Bignat z = temp;
        z.from_byte_array(z_arr);
        r.mod_add(z, n);
        Bignat s = k;
        s.mod_mult(k, r, n);
        Util.arrayCopy(s.as_byte_array(), (short)0, sigBuff, (short)(sigOffset+32), (short)32);
        // TODO: Deal with extreme case s=0
        */

        // Return result should technically be in ANS.1 format. Could do later.
        return (short)64;
    }

    public boolean verify(byte[] inBuff, short inOffset, short inLength, byte[] sigBuff, short sigOffset, short sigLength) {
        // TODO implement
        return true;
    }

}
