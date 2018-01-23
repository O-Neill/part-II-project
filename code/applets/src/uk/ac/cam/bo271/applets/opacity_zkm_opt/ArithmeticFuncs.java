package uk.ac.cam.bo271.applets.opacity_zkm_opt;

import javacard.framework.*;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.ECPrivateKey;

public class ArithmeticFuncs {

    public static void send(byte[] buf, short offset, short len, APDU apdu) {
        byte[] ret_buffer = apdu.getBuffer();

        short ret_len = apdu.setOutgoing();

        if (ret_len < len)
            ISOException.throwIt( ISO7816.SW_WRONG_LENGTH );

        apdu.setOutgoingLength(len);

        Util.arrayCopy(buf, offset, ret_buffer, (short)0, len);

        apdu.sendBytes((short)0, len);
    }

    // Array for temporary storage of old_r and r to reduce Bignat usage.
    public static byte[] r_arr = new byte[64];

    // Stripped-down version of egcd that only returns the x bezout coefficient.
    // Can modify to take a third argument which is the return value gcd.
    public static void egcd(Bigint a, Bigint b, Bignat temp1, Bignat temp2, Bignat temp3, Bignat temp4, APDU apdu) {

        // Return a = gcd, b = x (one bezout coefficient)
        Bignat q = temp1;
        Bigint temp = new Bigint(temp2);
        Bigint s = new Bigint(temp3);
        s.zero();

        Bignat old_r = a.getMagnitude();
        Bignat r = b.getMagnitude();

        // Initialise x1 = 1
        Bigint old_s = new Bigint(temp4);
        old_s.one();

        // while old_r > 1
        while(Bignat_Helper.ONE.smaller(old_r))
        {
            // q is quotient
            // q = old_r / r;

            q.clone(old_r);
            q.divide(r);

            // Temporarily store old_r and r values in array.
            old_r.copy_to_buffer(r_arr, (short)0);
            r.copy_to_buffer(r_arr, (short)32);
            Bignat temp5 = old_r;
            Bignat temp6 = r;

            // Should do a mathematical proof of correctness.
            // s = old_s - q * s; old_s = s
            Bigint qs = new Bigint(q);
            qs.mod_mult(qs, s, BignatStore.max_val, temp.getMagnitude(), temp5, temp6);

            temp.clone(s);
            s.clone(old_s);
            old_s.clone(temp);
            s.subtract(qs, temp.getMagnitude());

            // Restore values of old_r and r
            old_r.from_byte_array((short)32, (short)0, r_arr, (short)0);
            r.from_byte_array((short)32, (short)0, r_arr, (short)32);

            // old_r = r; r = old_r % r
            temp.getMagnitude().clone(r);
            old_r.mod(r);
            r.clone(old_r);

            old_r.clone(temp.getMagnitude());
        }

        // Return the value currently stored in x1.
        a.clone(old_s);
    }

    // When this returns, k contains its modular inverse.
    public static void mod_inv(Bignat k, Bignat mod, Bignat temp1, Bignat temp2, Bignat temp3, Bignat temp4, Bignat temp5, APDU apdu) {

        Bignat n = temp1;
        n.clone(mod);
        // TODO: If mod is one, no solution exists. Return 0.

        Bigint k_int = new Bigint(k);
        Bigint mod_int = new Bigint(n);


        egcd(k_int, mod_int, temp2, temp3, temp4, temp5, apdu);
        // Ensure positive
        k.mod(mod);

    }

    public static boolean at_infinity(ECPoint p) {
        // TODO: implement
        return false;
    }


    private static byte[] arr1 = new byte[32];
    private static byte[] ret_point = new byte[65];

    public static void point_add(ECPoint p, ECPoint q, ECPoint out, Bignat temp1, Bignat temp2, Bignat temp3, Bignat temp4, Bignat temp5, Bignat temp6, Bignat temp7, ECConfig m_ecc) {
        // TODO
        if (at_infinity(p)) {
            ISOException.throwIt((short)0x3802);
            // TODO: copy q to out
            return;
        } else if (at_infinity(q)) {
            ISOException.throwIt((short)0x3803);
            // TODO: copy p to out
            return;
        }

        Bignat lambda;

        p.getField(arr1, (short)0);
        Bignat prime = temp7;
        prime.from_byte_array(arr1);

        if (!p.isEqual(q)) {
            // p and q are not the same point, so calculate lambda accordingly.

            // TODO: More efficient to copy directly to value buffer.
            // Get y_p and y_q

            Bignat y_p = temp1;
            p.getY(arr1, (short)0);
            y_p.from_byte_array(arr1);
            Bignat y_q = temp2;
            q.getY(arr1, (short)0);
            y_q.from_byte_array(arr1);

            // TODO: Use Bignat.times_minus
            // Get d_y
            Bignat dy = temp3;
            dy.clone(y_q);
            dy.mod_sub(y_p, prime);

            // Get x_p and x_q
            Bignat x_p = temp1;
            p.getX(arr1, (short)0);
            x_p.from_byte_array(arr1);
            Bignat x_q = temp2;
            q.getX(arr1, (short)0);
            x_q.from_byte_array(arr1);

            // Get dx
            Bignat dx = x_q;
            dx.mod_sub(x_p, prime);

            // Take inverse of dx
            mod_inv(dx, prime, temp1, temp3, temp4, temp5, temp6, null);
            Bignat dx_inv = dx;

            // Calculate the modular gradient and hence lambda.
            dy.mod_mult(dy, dx_inv, prime);
            lambda = dy;

        } else {
            // p and q are the same point, so calculate lambda for the point
            // doubling case.

            // Get y coordinate.
            p.getY(arr1, (short)0);
            Bignat y_p = temp1;
            y_p.from_byte_array(arr1);

            // Lambda = (3 * x_p^2 + a) / 2 * y_p

            // Get inverse of lambda demonimator
            Bignat denom = y_p;
            denom.mod_add(y_p, prime);
            mod_inv(denom, prime, temp2, temp3, temp4, temp5, temp6, null);

            // Get x coordinate.

            p.getX(arr1, (short)0);
            Bignat x_p = temp3;
            x_p.from_byte_array(arr1);

            // Get lambda numerator
            Bignat num = x_p;
            num.mod_mult(x_p, x_p, prime);
            Bignat three = temp2;
            three.three();
            num.mod_mult(num, three, prime);
            p.getA(arr1, (short)0);
            temp3.from_byte_array(arr1);
            num.mod_add(temp3, prime);

            // Calculate lambda.
            lambda = num;
            lambda.mod_mult(num, denom, prime);
        }

        // lambda stored in temp3. Other temps unneeded.

        // Calculate lambda squared.
        Bignat lambda_squared = temp1;
        // TODO: Make sure this works.
        lambda_squared.mod_mult(lambda, lambda, prime);

        // Use lambda squared to calculate the X output.
        // Xout = lambda^2 - x_p - x_q
        Bignat Xout = lambda_squared;
        Bignat x_q = temp2;
        q.getX(arr1, (short)0);
        x_q.from_byte_array(arr1);
        Xout.mod_sub(x_q, prime);
        Bignat x_p = temp2;
        p.getX(arr1, (short)0);
        x_p.from_byte_array(arr1);
        Xout.mod_sub(x_p, prime);

        // Get Y output. Yout = lambda(x_p - Xout) - y_p
        Bignat Yout = x_p;
        Yout.mod_sub(Xout, prime);
        Yout.mod_mult(Yout, lambda, prime);
        Bignat y_p = temp3;
        p.getY(arr1, (short)0);
        y_p.from_byte_array(arr1);
        Yout.mod_sub(y_p, prime);

        ret_point[0] = (byte)0x04;
        Util.arrayCopy(Xout.as_byte_array(), (short)0, ret_point, (short)1, (short)32);
        Util.arrayCopy(Yout.as_byte_array(), (short)0, ret_point, (short)33, (short)32);
        out.setW(ret_point, (short)0, (short)65);
    }

    public static void point_double(ECPoint r, Bignat temp1, Bignat temp2, Bignat temp3, Bignat temp4, Bignat temp5, Bignat temp6, Bignat temp7, ECConfig ecc) {
        point_add(r, r, r, temp1, temp2, temp3, temp4, temp5, temp6, temp7, ecc);
    }

    public static void point_mult(ECPoint p, Bignat k, Bignat temp1, Bignat temp2, Bignat temp3, Bignat temp4, Bignat temp5, Bignat temp6, ECConfig ecc) {
        KeyAgreement dh = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);

        ECPrivateKey scalar = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, (short)256, false);
        byte[] scalar_val = k.as_byte_array();

        scalar.setA(SecP256r1.a, (short)0, (short)SecP256r1.a.length);
        scalar.setB(SecP256r1.b, (short)0, (short)SecP256r1.b.length);
        scalar.setFieldFP(SecP256r1.p, (short)0, (short)SecP256r1.p.length);
        scalar.setG(SecP256r1.G, (short)0, (short)SecP256r1.G.length);
        scalar.setK((short)0x01);
        scalar.setR(SecP256r1.r, (short)0, (short)SecP256r1.r.length);
        scalar.setS(scalar_val, (short)0, (short)scalar_val.length);

        dh.init(scalar);

        // TODO: What's the smallest array I can use?
        byte temp[] = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_DESELECT);

        // Throws CryptoException if pubkey formatted wrong.
        short len = 0;

        byte[] point = new byte[65];
        p.getW(point, (short)0);

        len = dh.generateSecret(point, (short)0, (short)point.length, temp, (byte)0);

        // TODO: Double check len.
        Util.arrayCopy(temp, (byte)0, point, (short)0, len);
        // Not quite right. This only returns the x coordinate.
        p.setW(point, (short)0, (short)point.length);
        /*
        byte[] temp_arr = new byte[65];
        p.getField(temp_arr, (short)0);
        Bignat prime = temp1;
        prime.from_byte_array((short)32, (short)0, temp_arr, (short)0);

        short klen = k.length();

        k.mod(prime);

        // Initialse Q to 0, N to p
        Util.arrayFillNonAtomic(temp_arr, (short)0, (short)65, (byte)0x00);
        temp_arr[0] = (byte)0x04;
        ECPoint Q = new ECPoint(p.getCurve(), ecc.ech);
        Q.setW(temp_arr, (short)0, (short)65);
        ECPoint N = new ECPoint(p.getCurve(), ecc.ech);
        p.getW(temp_arr, (short)0);
        N.setW(temp_arr, (short)0, (short)65);

        // Save k's value in the buffer, use k as a temporary Bignat, restore later.
        k.copy_to_buffer(temp_arr, (short)0);
        byte[] k_bytes = temp_arr;
        Bignat temp7 = k;

        for (short i = (short)(klen - 1); i >= 0; i--) {
            point_double(Q, temp1, temp2, temp3, temp4, temp5, temp6, temp7, ecc);
            for (short bit = 7; bit <= 0; bit--) {
                if (((k_bytes[i] >> bit) & 1) == 0x01) {
                    // d_i = 1
                    point_add(Q, p, Q, temp1, temp2, temp3, temp4, temp5, temp6, temp7, ecc);
                }
            }
            if (i == (short)(klen - 4))
                ISOException.throwIt((short)0x4444);
        }

        // Restore original value of k.
        k.from_byte_array(k_bytes);

        return Q;
        */
    }

}
