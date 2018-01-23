package uk.ac.cam.bo271.applets.opacity_zkm_opt;

import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyPair;
import javacard.security.Signature;

/**
 *
 * @author Vasilios Mavroudis and Petr Svenda
 */
public class ECPoint {
    private final ECPoint_Helper ech;

    private ECPublicKey         thePoint;
    private KeyPair             thePointKeyPair;
    private final ECCurve       theCurve;

    /**
     * Creates new ECPoint object for provided {@code curve}. Random initial point value is generated.
     * The point will use helper structures from provided ECPoint_Helper object.
     * @param curve point's elliptic curve
     * @param ech object with preallocated helper objects and memory arrays
     */
    public ECPoint(ECCurve curve, ECPoint_Helper ech) {
        this.theCurve = curve;
        this.ech = ech;
        updatePointObjects();
    }

    /**
     * Returns length of this point in bytes.
     *
     * @return
     */
    public short length() {
        return (short) (thePoint.getSize() / 8);
    }

    /**
     * Properly updates all point values in case of a change of an underlying curve.
     * New random point value is generated.
     */
    public final void updatePointObjects() {
        this.thePointKeyPair = this.theCurve.newKeyPair(this.thePointKeyPair);
        this.thePoint = (ECPublicKey) thePointKeyPair.getPublic();
    }
    /**
     * Generates new random point value.
     */
    public void randomize(){
        if (this.thePointKeyPair == null) {
            this.thePointKeyPair = this.theCurve.newKeyPair(this.thePointKeyPair);
            this.thePoint = (ECPublicKey) thePointKeyPair.getPublic();
        }
        else {
            this.thePointKeyPair.genKeyPair();
        }
    }

    /**
     * Copy value of provided point into this. This and other point must have
     * curve with same parameters, only length is checked.
     * @param other point to be copied
     */
    public void copy(ECPoint other) {
        if (this.length() != other.length()) {
            ISOException.throwIt(ReturnCodes.SW_ECPOINT_INVALIDLENGTH);
        }
        ech.lock(ech.uncompressed_point_arr1);
        short len = other.getW(ech.uncompressed_point_arr1, (short) 0);
        this.setW(ech.uncompressed_point_arr1, (short) 0, len);
        ech.unlock(ech.uncompressed_point_arr1);
    }

    /**
     * Set this point value (parameter W) from array with value encoded as per ANSI X9.62.
     * The uncompressed form is always supported. If underlying native JavaCard implementation
     * of {@code ECPublickKey} supports compressed points, then this method accepts also compressed points.
     * @param buffer array with serialized point
     * @param offset start offset within input array
     * @param length length of point
     */
    public void setW(byte[] buffer, short offset, short length) {
        this.thePoint.setW(buffer, offset, length);
    }

    /**
     * Returns current value of this point.
     * @param buffer    memory array where to store serailized point value
     * @param offset    start offset for output serialized point
     * @return length of serialized point (number of bytes)
     */
    public short getW(byte[] buffer, short offset) {
        return thePoint.getW(buffer, offset);
    }

    /**
     * Returns this point value as ECPublicKey object. No copy of point is made
     * before return, so change of returned object will also change this point value.
     * @return point as ECPublicKey object
     */
    public ECPublicKey asPublicKey() {
        return this.thePoint;
    }

    /**
     * Returns curve associated with this point. No copy of curve is made
     * before return, so change of returned object will also change curve for
     * this point.
     *
     * @return curve as ECCurve object
     */
    public ECCurve getCurve() {
    	return theCurve;
    }

    /**
     * Returns the X coordinate of this point in uncompressed form.
     * @param buffer output array for X coordinate
     * @param offset start offset within output array
     * @return length of X coordinate (in bytes)
     */
    public short getX(byte[] buffer, short offset) {
        ech.lock(ech.uncompressed_point_arr1);
        thePoint.getW(ech.uncompressed_point_arr1, (short) 0);
        Util.arrayCopyNonAtomic(ech.uncompressed_point_arr1, (short) 1, buffer, offset, this.theCurve.COORD_SIZE);
        ech.unlock(ech.uncompressed_point_arr1);
        return this.theCurve.COORD_SIZE;
    }

    /**
     * Returns the Y coordinate of this point in uncompressed form.
     *
     * @param buffer output array for Y coordinate
     * @param offset start offset within output array
     * @return length of Y coordinate (in bytes)
     */
    public short getY(byte[] buffer, short offset) {
        ech.lock(ech.uncompressed_point_arr1);
        thePoint.getW(ech.uncompressed_point_arr1, (short) 0);
        Util.arrayCopyNonAtomic(ech.uncompressed_point_arr1, (short)(1 + this.theCurve.COORD_SIZE), buffer, offset, this.theCurve.COORD_SIZE);
        ech.unlock(ech.uncompressed_point_arr1);
        return this.theCurve.COORD_SIZE;
    }
    /**
     * Returns the Y coordinate of this point in form of Bignat object.
     *
     * @param yCopy Bignat object which will be set with value of this point
     */
    public void getY(Bignat yCopy) {
        yCopy.set_size(this.getY(yCopy.as_byte_array(), (short) 0));
    }

    /**
     * Compares this and provided point for equality. The comparison is made using hash of both values to prevent leak of position of mismatching byte.
     * @param other second point for comparison
     * @return true if both point are exactly equal (same length, same value), false otherwise
     */
    public boolean isEqual(ECPoint other) {
        boolean bResult = false;
        if (this.length() != other.length()) {
            return false;
        }
        else {
            // The comparison is made with hash of point values instead of directly values.
            // This way, offset of first mismatching byte is not leaked via timing side-channel.
            // Additionally, only single array is required for storage of plain point values thus saving some RAM.
            ech.lock(ech.uncompressed_point_arr1);
            ech.lock(ech.fnc_isEqual_hashArray);
            //ech.lock(ech.fnc_isEqual_hashEngine);
            short len = this.getW(ech.uncompressed_point_arr1, (short) 0);
            ech.fnc_isEqual_hashEngine.doFinal(ech.uncompressed_point_arr1, (short) 0, len, ech.fnc_isEqual_hashArray, (short) 0);
            len = other.getW(ech.uncompressed_point_arr1, (short) 0);
            len = ech.fnc_isEqual_hashEngine.doFinal(ech.uncompressed_point_arr1, (short) 0, len, ech.uncompressed_point_arr1, (short) 0);
            bResult = Util.arrayCompare(ech.fnc_isEqual_hashArray, (short) 0, ech.uncompressed_point_arr1, (short) 0, len) == 0;
            //ech.unlock(ech.fnc_isEqual_hashEngine);
            ech.unlock(ech.fnc_isEqual_hashArray);
            ech.unlock(ech.uncompressed_point_arr1);
        }

        return bResult;
    }

    static byte[] msg = {(byte) 0x01, (byte) 0x01, (byte) 0x02, (byte) 0x03};
    public static boolean SignVerifyECDSA(ECPrivateKey privateKey, ECPublicKey publicKey, Signature signEngine, byte[] tmpSignArray) {
        signEngine.init(privateKey, Signature.MODE_SIGN);
        short signLen = signEngine.sign(msg, (short) 0, (short) msg.length, tmpSignArray, (short) 0);
        signEngine.init(publicKey, Signature.MODE_VERIFY);
        return signEngine.verify(msg, (short) 0, (short) msg.length, tmpSignArray, (short) 0, signLen);
    }


    //
    // ECKey methods
    //
    public void setFieldFP(byte[] bytes, short s, short s1) throws CryptoException {
        thePoint.setFieldFP(bytes, s, s1);
    }

    public void setFieldF2M(short s) throws CryptoException {
        thePoint.setFieldF2M(s);
    }

    public void setFieldF2M(short s, short s1, short s2) throws CryptoException {
        thePoint.setFieldF2M(s, s1, s2);
    }

    public void setA(byte[] bytes, short s, short s1) throws CryptoException {
        thePoint.setA(bytes, s, s1);
    }

    public void setB(byte[] bytes, short s, short s1) throws CryptoException {
        thePoint.setB(bytes, s, s1);
    }

    public void setG(byte[] bytes, short s, short s1) throws CryptoException {
        thePoint.setG(bytes, s, s1);
    }

    public void setR(byte[] bytes, short s, short s1) throws CryptoException {
        thePoint.setR(bytes, s, s1);
    }

    public void setK(short s) {
        thePoint.setK(s);
    }

    public short getField(byte[] bytes, short s) throws CryptoException {
        return thePoint.getField(bytes, s);
    }

    public short getA(byte[] bytes, short s) throws CryptoException {
        return thePoint.getA(bytes, s);
    }

    public short getB(byte[] bytes, short s) throws CryptoException {
        return thePoint.getB(bytes, s);
    }

    public short getG(byte[] bytes, short s) throws CryptoException {
        return thePoint.getG(bytes, s);
    }

    public short getR(byte[] bytes, short s) throws CryptoException {
        return thePoint.getR(bytes, s);
    }

    public short getK() throws CryptoException {
        return thePoint.getK();
    }
}
