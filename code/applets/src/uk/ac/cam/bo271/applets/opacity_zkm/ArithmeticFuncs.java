package uk.ac.cam.bo271.applets.opacity_zkm;

import javacard.framework.*;


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

    // TODO: Update so new thing isn't reassigned each time.

    public static void egcd(Bignat a, Bignat b, Bignat x_out, Bignat y_out, Bignat g_out, ECConfig ecc, APDU apdu) {
        Bignat bound;
        if (a.lesser(b)) {
            bound = b;
        } else {
            bound = a;
        }
        JCSystem.requestObjectDeletion();
        Bignat last_r = g_out;
        last_r.copy(a);
        Bignat r = new Bignat((short)32, JCSystem.CLEAR_ON_RESET, ecc.bnh);
        r.copy(b);

        // Initialise x, last_x, y, last_y.
        // (Using Integers because intermediate values may be negative)
        Bignat x_nat = new Bignat((short)32, JCSystem.CLEAR_ON_RESET, ecc.bnh);
        x_nat.zero();
        Integer x = new Integer((byte)0, x_nat, false, ecc.bnh);
        x_out.one();
        Integer last_x = new Integer((byte)0, x_out, false, ecc.bnh);

        Bignat y_nat = new Bignat((short)32, JCSystem.CLEAR_ON_RESET, ecc.bnh);
        y_nat.one();
        Integer y = new Integer((byte)0, y_nat, false, ecc.bnh);
        y_out.zero();
        Integer last_y = new Integer((byte)0, y_out, false, ecc.bnh);


        Bignat temp = new Bignat((short)32, JCSystem.CLEAR_ON_RESET, ecc.bnh);
        Bignat temp2 = new Bignat((short)32, JCSystem.CLEAR_ON_RESET, ecc.bnh);
        Integer temp_int = new Integer((byte)0, temp, false, ecc.bnh);
        Integer temp_int2 = new Integer((byte)0, temp2, false, ecc.bnh);
        Bignat quotient = new Bignat((short)32, JCSystem.CLEAR_ON_RESET, ecc.bnh);
        Integer quotient_int = new Integer((byte)0, quotient, false, ecc.bnh);

        short passesSinceCleanup = 0;

        while (!r.is_zero()) {
            last_r.remainder_divide(r, quotient);
            temp.copy(last_r);
            last_r.copy(r);
            r.copy(temp);

            // mod_mult should be the same as mult, it just means I don't need
            // an output of a different size.
            // x, lastx = lastx - quotient * x, x
            temp_int.clone(x);
            temp_int2.clone(quotient_int);

            if (passesSinceCleanup == (short)12) {
/*
                byte[] ret = new byte[64];
                Util.arrayCopy(x.getMagnitude().as_byte_array(), (short)0, ret, (short)0, (short)32);
                Util.arrayCopy(temp_int2.getMagnitude().as_byte_array(), (short)0, ret, (short)32, (short)32);

                if (x.isNegative()) {
                    ISOException.throwIt((byte)0x2342);
                }
                if (temp_int2.isNegative()) {
                    ISOException.throwIt((byte)0x2343);
                }
*/

                //temp_int2.getMagnitude().mod_mult(temp_int2.getMagnitude(), x.getMagnitude(), bound);

                return;

            }
            temp_int2.multiply(x);

            x.clone(last_x);
            x.subtract(temp_int2);
            last_x.clone(temp_int);

            // y, lasty = lasty - quotient * y, y
            temp_int.clone(y);
            temp_int2.clone(quotient_int);
            temp_int2.multiply(y);
            y.clone(last_y);
            y.subtract(temp_int2);
            last_y.clone(temp_int);

            passesSinceCleanup++;

            if (passesSinceCleanup == (short)10) {
                // It would fail before 12 passes previously, cleanup necessary.
                // Don't want to clean up too often though.
                JCSystem.requestObjectDeletion();
                //passesSinceCleanup = 0;
            }
        }


        // Now x_out, y_out, g_out = abs(last_x), abs(last_y), abs(old_r)
    }

    // When this returns, k contains its modular inverse.
    public static void mod_inv(Bignat k, Bignat mod, Bignat_Helper bnh, APDU apdu) {
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
                }
            }
        }
        if (is_one) {
            k.zero();
            return;
        }

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
            // q = k / n;
            q.copy(k);
            q.divide(n);

            // t = n;
            t.copy(n);

            // m is remainder now, process
            // same as Euclid's algo
            // m = a % n; k = t
            k.mod(n);
            n.copy(k);
            k.copy(t);

            // t = x0
            t.copy(x0);

            // x0 = x1 - q * x0;
            intermediate.mult(q, x0);
            x0.copy(x1);
            x0.subtract(intermediate);

            // x1 = t;
            x1.copy(t);
        }

        // Make x1 positive
        if (x1.smaller(zero))
            x1.add(n0);

        // Return the value currently stored in x1.
        k.copy(x1);
    }

    public static boolean at_infinity(ECPoint p) {
        // TODO: implement
        return false;
    }

    public static ECPoint point_add(ECPoint p, ECPoint q, ECConfig m_ecc, APDU apdu) {
        if (at_infinity(p)) {
            ISOException.throwIt((short)0x3802);
            return q;
        } else if (at_infinity(q)) {
            ISOException.throwIt((short)0x3803);
            return p;
        }

        byte[] temp_arr = new byte[32];
        Bignat lambda;
        byte[] prime_arr = new byte[32];
        p.getField(prime_arr, (short)0);
        Bignat prime = new Bignat(prime_arr, m_ecc.bnh);

        Bignat x_p;
        Bignat x_q;
        Bignat y_p;
        Bignat y_q;

        Bignat intermediate1 = new Bignat((short)32, JCSystem.CLEAR_ON_RESET, m_ecc.bnh);
        Bignat intermediate2 = new Bignat((short)32, JCSystem.CLEAR_ON_RESET, m_ecc.bnh);

        if (!p.isEqual(q)) {
            // p and q are not the same point, so calculate lambda accordingly.

            // Get y_p and y_q
            byte[] y_p_arr = new byte[32];
            p.getY(y_p_arr, (short)0);
            y_p = new Bignat(y_p_arr, m_ecc.bnh);
            byte[] y_q_arr = new byte[32];
            q.getY(y_q_arr, (short)0);
            y_q = new Bignat(y_q_arr, m_ecc.bnh);

            // Get d_y
            Bignat dy = intermediate1;
            dy.copy(y_q);
            dy.mod_sub(y_p, prime);

            // Get x_p and x_q
            byte[] x_p_arr = new byte[32];
            p.getX(x_p_arr, (short)0);
            x_p = new Bignat(x_p_arr, m_ecc.bnh);
            byte[] x_q_arr = new byte[32];
            q.getX(x_q_arr, (short)0);
            x_q = new Bignat(x_q_arr, m_ecc.bnh);

            // Get dx
            Bignat dx = intermediate2;
            dx.copy(x_q);
            dx.mod_sub(x_p, prime);

            // Take inverse of dx
            mod_inv(dx, prime, m_ecc.bnh, apdu);
            Bignat dx_inv = dx;

            if (p != null) {
                //send(prime.as_byte_array(), (short)0, (short)32, apdu);
                return null;
            }


            // Calculate the modular gradient and hence lambda.
            dy.mod_mult(dy, dx_inv, prime);
            lambda = dy;

        } else {
            ISOException.throwIt((short)0x3801);
            // p and q are the same point, so calculate lambda for the point
            // doubling case.

            // Get coordinates.
            byte[] x_arr = new byte[32];
            p.getX(x_arr, (short)0);
            x_p = new Bignat(x_arr, m_ecc.bnh);
            x_q = x_p;
            byte[] y_arr = new byte[32];
            p.getY(y_arr, (short)0);
            y_p = new Bignat(y_arr, m_ecc.bnh);
            y_q = y_p;

            // Lambda = (3 * x_p^2 + a) / 2 * y_p

            // Get lambda numerator
            Bignat num = intermediate1;
            num.mod_mult(x_p, x_p, prime);
            num.mod_mult(num, Bignat_Helper.THREE, prime);
            p.getA(temp_arr, (short)0);
            Bignat a = new Bignat(temp_arr, m_ecc.bnh);
            num.mod_add(a, prime);

            // Get inverse of lambda demonimator
            Bignat denom = intermediate2;
            denom.copy(y_p);
            denom.mod_add(y_p, prime);
            mod_inv(denom, prime, m_ecc.bnh, apdu);

            // Calculate lambda.
            lambda = num;
            lambda.mod_mult(num, denom, prime);
        }

        // Calculate lambda squared.
        Bignat lambda_squared = intermediate1;
        lambda_squared.copy(lambda);
        lambda_squared.mod_mult(lambda, lambda_squared, prime);

        // Use lambda squared to calculate the X output.
        // Xout = lambda^2 - x_p - x_q
        Bignat Xout = lambda_squared;
        Xout.mod_sub(x_p, prime);
        Xout.mod_sub(x_q, prime);

        // Get Y output. Yout = lambda(x_p - Xout) - y_p
        Bignat Yout = x_p;
        Yout.mod_sub(Xout, prime);
        Yout.mod_mult(Yout, lambda, prime);
        Yout.mod_sub(y_p, prime);

        // Create new ECPoint and initialise to newly calculated coordinates.
        ECPoint pt = new ECPoint(p.getCurve(), m_ecc.ech);
        byte[] ret_point = new byte[65];
        ret_point[0] = (byte)0x04;
        Util.arrayCopy(Xout.as_byte_array(), (short)0, ret_point, (short)1, (short)32);
        Util.arrayCopy(Yout.as_byte_array(), (short)0, ret_point, (short)33, (short)32);
        pt.setW(ret_point, (short)0, (short)65);
        return pt;
    }

    public static ECPoint point_double(ECPoint r, ECConfig ecc, APDU apdu) {
        return point_add(r, r, ecc, apdu);
    }

    public static ECPoint point_mult(ECPoint p, Bignat k, ECConfig ecc, APDU apdu) {


        short bitLength = (short)(k.length() * 8);

        byte[] prime_arr = new byte[32];
        p.getField(prime_arr, (short)0);
        Bignat prime = new Bignat(prime_arr, ecc.bnh);

        // Initialse Q to 0, N to p
        byte[] point_val = new byte[65];
        point_val[0] = (byte)0x04;
        ECPoint Q = new ECPoint(p.getCurve(), ecc.ech);
        Q.setW(point_val, (short)0, (short)65);
        ECPoint N = new ECPoint(p.getCurve(), ecc.ech);
        p.getW(point_val, (short)0);
        N.setW(point_val, (short)0, (short)65);

        k.mod(prime);
        byte[] k_bytes = k.as_byte_array();

        for (short i = (short)(k.length() - 1); i >= 0; i--) {
            Q = point_double(Q, ecc, apdu);
            byte curr = k_bytes[i];
            for (short bit = 7; bit <= 0; bit--) {
                if (((k_bytes[i] >> bit) & 1) == 0x01) {
                    // d_i = 1
                    Q = point_add(Q, p, ecc, apdu);
                }
            }
        }
        return Q;
    }

}
