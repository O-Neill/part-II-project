package uk.ac.cam.bo271.applets.opacity_zkm;

import javacard.framework.*;

// Similar idea as Integer.java but simplified to mitigate possible problems.
public class Bigint{
    // Sign of the int. 0 for positive, 1 for negative.
    private byte sign;

    // Magnitude.
    private Bignat magnitude;

    private static Bignat swap_val;

    private static Bigint temp_val_1;
    private static Bigint temp_val_2;

    public static void init(Bignat_Helper bnh) {
        swap_val = new Bignat((short)32, JCSystem.CLEAR_ON_RESET, bnh);
        temp_val_1 = new Bigint(new Bignat((short)32, JCSystem.CLEAR_ON_RESET, bnh));
        temp_val_2 = new Bigint(new Bignat((short)32, JCSystem.CLEAR_ON_RESET, bnh));
    }

    public Bigint(Bignat mag) {
        this.magnitude = mag;
        this.sign = (byte)0;
    }

    public void zero() {
        this.sign = (byte)0;
        this.magnitude.zero();
    }

    public void one() {
        this.sign = (byte)0;
        this.magnitude.one();
    }

    public Bignat getMagnitude() {
        return this.magnitude;
    }

    public byte getSign() {
        return this.sign;
    }

    public void setSign(byte s) {
        this.sign = s;
    }

    public void clone(Bigint other) {
        this.sign = other.sign;
        this.magnitude.clone(other.getMagnitude());
    }

    public void subtract(Bigint other) {
        // TODO: If this is bigger
        if (this.sign == other.getSign()) {
            // Signs are equal, subtract magnitudes.
            if (this.magnitude.lesser(other.getMagnitude())) {
                // Other number is larger.
                // Flip sign.
                if (this.sign == 0) {
                    this.sign = (byte)1;
                } else {
                    this.sign = (byte)0;
                }

                swap_val.copy(other.getMagnitude());
                swap_val.subtract(this.magnitude);
                this.magnitude.copy(swap_val);
            } else {
                // This number is larger
                this.magnitude.subtract(other.getMagnitude());
            }
        } else {
            // If signs are different, add magnitudes.
            // TODO: Handle overflow.
            this.magnitude.add(other.getMagnitude());
        }
    }

    public void mod(Bignat modulo) {
        // Bring to within 'modulo' of zero.
        this.magnitude.mod(modulo);

        // If negative, add 'modulo' to it to make it positive.
        if (this.sign == (byte)1) {
            this.sign = (byte)0;

            swap_val.copy(modulo);
            swap_val.subtract(this.magnitude);
            this.magnitude.copy(swap_val);
        }
    }

    public void mod_mult(Bigint x, Bigint y, Bignat modulo) {
        // Take modulo of inputs, ensuring we end up with non-negative values.
        this.sign = 0;
        temp_val_1.clone(x);
        temp_val_2.clone(y);
        temp_val_1.mod(modulo);
        temp_val_2.mod(modulo);
        this.magnitude.mod_mult(temp_val_1.getMagnitude(), temp_val_2.getMagnitude(), modulo);
    }


}
