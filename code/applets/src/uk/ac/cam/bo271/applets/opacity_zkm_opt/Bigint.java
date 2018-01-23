package uk.ac.cam.bo271.applets.opacity_zkm_opt;

// Similar idea as Integer.java but simplified to mitigate possible problems.
public class Bigint{
    // Sign of the int. 0 for positive, 1 for negative.
    private byte sign;

    // Magnitude.
    private Bignat magnitude;

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
        // Is copy better?
        this.magnitude.clone(other.getMagnitude());
    }

    public void subtract(Bigint other, Bignat temp) {
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

                temp.clone(other.getMagnitude());
                temp.subtract(this.magnitude);
                this.magnitude.clone(temp);
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

    public void mod(Bignat modulo, Bignat temp) {
        // Bring to within 'modulo' of zero.
        this.magnitude.mod(modulo);

        // If negative, add 'modulo' to it to make it positive.
        if (this.sign == (byte)1) {
            this.sign = (byte)0;

            temp.clone(modulo);
            temp.subtract(this.magnitude);
            this.magnitude.clone(temp);
        }
    }

    public void mod_mult(Bigint x, Bigint y, Bignat modulo, Bignat temp1, Bignat temp2, Bignat temp3) {
        // Take modulo of inputs, ensuring we end up with non-negative values.
        this.sign = 0;
        Bigint temp_int1 = new Bigint(temp1);
        Bigint temp_int2 = new Bigint(temp2);
        temp_int1.clone(x);
        temp_int2.clone(y);
        temp_int1.mod(modulo, temp3);
        temp_int2.mod(modulo, temp3);
        this.magnitude.mod_mult(temp_int1.getMagnitude(), temp_int2.getMagnitude(), modulo);
    }
}
