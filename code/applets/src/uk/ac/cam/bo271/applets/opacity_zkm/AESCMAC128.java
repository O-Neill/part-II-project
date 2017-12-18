package uk.ac.cam.bo271.applets.opacity_zkm;
import javacard.security.Signature;
import javacard.security.AESKey;
import javacard.security.Key;
import javacardx.crypto.Cipher;
import javacard.security.KeyBuilder;
import javacard.framework.*;
import javacard.security.CryptoException;

// CMAC signature defined in Java Card 3.0.5 API but not in Java Card 2.2.2.
// Have to produce my own implementation, may as well conform to existing
// abstract class.
public class AESCMAC128 extends Signature {


    // Constant to be XORed with last byte in subkey generation, defined in
    // NIST 800-38B standards.
    private static byte Rb = (byte) 0x87;
    private byte[] k1;
    private byte[] k2;
    private AESKey aesKey;

    private byte ciphermode;
    private byte[] cipher;

    // TODO: Initialise and use.
    private byte[] k;
    private byte[] lastBlock;

    public AESCMAC128() {
        // TODO:

    }

    private void leftShiftArray(byte[] buffer) {
        byte c = 0;
        for (short i = (short)(buffer.length - 1); i >= 0; i--) {
            // carry msb in buffer
            c = (byte)(buffer[i]>>7);

            buffer[i] = (byte)(buffer[i]<<1);

            // If not leftmost byte, carry msb of current byte to the next byte.
            if (i > 0) {
                buffer[(short)(i+1)] += c;
            }
        }
    }

    // Calling this method repeatedly will generate key rotations that can be
    // used as subkeys (as per the NIST 800-38B standards)
    private void subkeys(byte[] k) {
        // TODO: Check size of k = 16

        // Step 1 of subkey generation - encrypt a 0-block using the key k.
        Cipher AESCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
        AESCipher.init(aesKey, ciphermode);

        // Cipher block of 0s.
        Util.arrayFillNonAtomic(k, (short)0, (short)16, (byte)0);
        AESCipher.doFinal(k, (short)0, (short)16, k, (short)0);
        // At this stage k = L

        // Step 2 - if leftmost bit of L is 0, k1=L<<1 else k1=(L<<1)^Rb
        byte msb = (byte) (k[0] >> 7);  // 0 or 1 depending on msb of L

        // In either case need to left-shift.
        leftShiftArray(k);

        // If msb was 1, XOR shifted array with Rb
        if (msb != 0) {
            k[15] ^= Rb;
        }
    }

    public byte getAlgorithm() {
        // value of ALG_AES_CMAC_128 in the JavaCard 3.0.5 API.
        return (byte) 49;
    }

    // Returns the byte length of the signature data.
    public short getLength() {
        // CMAC length is 16 bytes.
        return (short) 16;
    }

    // Initialise signature object with appropriate key
    public void init(Key key, byte mode) {
        init(key, mode, null, (short)0, (short)0);
    }

    public void init(Key key, byte mode, byte[] init_info, short off, short len) {
        // TODO: init_info should contain anything?

        // initialise CBC-MAC helper
        aesKey = (AESKey) key;
        k = JCSystem.makeTransientByteArray((short)16, JCSystem.CLEAR_ON_DESELECT);
        ciphermode = mode;

        // Compute and store keys k1 and k2.
        aesKey.getKey(k, (short)0);
        k1 = JCSystem.makeTransientByteArray((short)16, JCSystem.CLEAR_ON_DESELECT);
        Util.arrayCopy(k, (short)0, k1, (short)0, (short)16);
        subkeys(k1);
        k2 = JCSystem.makeTransientByteArray((short)16, JCSystem.CLEAR_ON_DESELECT);
        Util.arrayCopy(k1, (short)0, k2, (short)0, (short)16);
        subkeys(k2);
        cipher = JCSystem.makeTransientByteArray((short)16, JCSystem.CLEAR_ON_DESELECT);
        lastBlock = JCSystem.makeTransientByteArray((short)16, JCSystem.CLEAR_ON_DESELECT);
    }

    public short sign(byte[] input, short inOffset, short len, byte[] sigBuff, short sigOffset) {
        // TODO: If last block is incomplete, pad with 1 followed by 0s.
        // Then XOR with k1

        // Number of complete blocks (minus the last one if the last is complete)
        short fullBlocks = (short)(len-1/16);  // Number of blocks before last.
        short fullBlocksLen = (short)(16 * fullBlocks);

        // Step 4
        // Get last (possibly incomplete) block
        Util.arrayCopy(input, (short)(inOffset + fullBlocksLen), lastBlock,
                                                        (short)0, (short)16);

        if ((short)(len - fullBlocksLen) == 16) {
            // Last block takes up entire block, XOR with k1
            for (short i = 0; i < 16; i++) {
                lastBlock[i] = (byte)(lastBlock[i] ^ k1[i]);
            }
        } else {
            short numBytes = (short)(len - fullBlocksLen);
            // Pad last block with 1 followed by 0s and XOR with k2
            lastBlock[numBytes] = 0x08;
            for (short i = (short)(numBytes + 1); i < 16; i++) {
                lastBlock[i] = 0x00;
            }
            for (short i = 0; i < 16; i++) {
                lastBlock[i] = (byte)(lastBlock[i] ^ k2[i]);
            }
        }

        Cipher AESCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
        AESCipher.init(aesKey, ciphermode);

        // Step 6
        for (short i = 0; i < fullBlocks; i++) {
            for (short j = 0; j < 16; j++) {
                cipher[j] = (byte)(cipher[j] ^ input[(short)(i*16+j)]);
            }
            AESCipher.doFinal(cipher, (short)0, (short)16, cipher, (short)0);
        }
        for (short j = 0; j < 16; j++) {
            cipher[j] = (byte)(cipher[j] ^ lastBlock[j]);
        }
        AESCipher.doFinal(cipher, (short)0, (short)16, cipher, (short)0);
        Util.arrayCopy(cipher, (short)0, sigBuff, sigOffset, (short)16);
        return 16;
    }

    public void update(byte[] input, short inOffset, short len) {

        // input should be positive multiple of block size
        if (len == 0 || (len % 16 != 0)) {
            CryptoException.throwIt(CryptoException.ILLEGAL_USE);
        }

        Cipher AESCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
        AESCipher.init(aesKey, ciphermode);

        short blocks = (short)(len / 16);

        for (short i = 0; i < blocks; i++) {
            for (short j = 0; j < 16; j++) {
                cipher[j] = (byte)(cipher[j] ^ input[(short)(inOffset + i*16 + j)]);
            }
            AESCipher.doFinal(cipher, (short)0, (short)16, cipher, (short)0);
        }
    }

    public boolean verify(byte[] input, short inOffset, short len,
                          byte[] sigBuff, short sigOffset, short sigLen) {
        if (sigLen != 16) {
            return false;
        }

        // TODO: Timing attack?
        byte[] t = JCSystem.makeTransientByteArray((short)16, JCSystem.CLEAR_ON_DESELECT);
        sign(input, inOffset, len, t, (short)0);
        for (short i = 0; i < sigLen; i++) {
            if (sigBuff[(short)(i+sigOffset)] != t[i]) {
                return false;
            }
        }
        return true;
    }
/*
    public static void test() {

        // Tests this implementation according to https://tools.ietf.org/html/rfc4493#section-2.4

        Signature sig = (Signature) new AESCMAC128();
        short ZERO = 0;

        byte[] k = new byte[] {
            (byte)0x2B, (byte)0x7E, (byte)0x15, (byte)0x16, (byte)0x28, (byte)0xAE, (byte)0xD2, (byte)0xA6,
            (byte)0xAB, (byte)0xF7, (byte)0x15, (byte)0x88, (byte)0x09, (byte)0xCF, (byte)0x4F, (byte)0x3C
        }; // Length 16 bytes

        byte[] d1 = new byte[0];
        // Expect bb1d6929 e9593728 7fa37d12 9b756746

        byte[] d2 = new byte[] {
            (byte)0x6B, (byte)0xC1, (byte)0xBE, (byte)0xE2, (byte)0x2E, (byte)0x40, (byte)0x9F, (byte)0x96,
            (byte)0xE9, (byte)0x3D, (byte)0x7E, (byte)0x11, (byte)0x73, (byte)0x93, (byte)0x17, (byte)0x2A
        }; // Length 16 bytes
        // Expect 070a16b4 6b4d4144 f79bdd9d d04a287c

        byte[] d3 = new byte[] {
            (byte)0x6B, (byte)0xC1, (byte)0xBE, (byte)0xE2, (byte)0x2E, (byte)0x40, (byte)0x9F, (byte)0x96,
            (byte)0xE9, (byte)0x3D, (byte)0x7E, (byte)0x11, (byte)0x73, (byte)0x93, (byte)0x17, (byte)0x2A,
            (byte)0xAE, (byte)0x2D, (byte)0x8A, (byte)0x57, (byte)0x1E, (byte)0x03, (byte)0xAC, (byte)0x9C,
            (byte)0x9E, (byte)0xB7, (byte)0x6F, (byte)0xAC, (byte)0x45, (byte)0xAF, (byte)0x8E, (byte)0x51,
            (byte)0x30, (byte)0xC8, (byte)0x1C, (byte)0x46, (byte)0xA3, (byte)0x5C, (byte)0xE4, (byte)0x11
         }; // Length 40 bytes
        // Expect dfa66747 de9ae630 30ca3261 1497c827

        byte[] d4 = new byte[] {
            (byte)0x6B, (byte)0xC1, (byte)0xBE, (byte)0xE2, (byte)0x2E, (byte)0x40, (byte)0x9F, (byte)0x96,
            (byte)0xE9, (byte)0x3D, (byte)0x7E, (byte)0x11, (byte)0x73, (byte)0x93, (byte)0x17, (byte)0x2A,
            (byte)0xAE, (byte)0x2D, (byte)0x8A, (byte)0x57, (byte)0x1E, (byte)0x03, (byte)0xAC, (byte)0x9C,
            (byte)0x9E, (byte)0xB7, (byte)0x6F, (byte)0xAC, (byte)0x45, (byte)0xAF, (byte)0x8E, (byte)0x51,
            (byte)0x30, (byte)0xC8, (byte)0x1C, (byte)0x46, (byte)0xA3, (byte)0x5C, (byte)0xE4, (byte)0x11,
            (byte)0xE5, (byte)0xFB, (byte)0xC1, (byte)0x19, (byte)0x1A, (byte)0x0A, (byte)0x52, (byte)0xEF,
            (byte)0xF6, (byte)0x9F, (byte)0x24, (byte)0x45, (byte)0xDF, (byte)0x4F, (byte)0x9B, (byte)0x17,
            (byte)0xAD, (byte)0x2B, (byte)0x41, (byte)0x7B, (byte)0xE6, (byte)0x6C, (byte)0x37, (byte)0x10
         }; // Length 64 bytes
        // Expect 51f0bebf 7e3b9d92 fc497417 79363cfe

        byte[] m = new byte[16];
        boolean ok = false;

        AESKey key = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        key.setKey(k, ZERO);

        sig.init(key, Signature.MODE_SIGN);
        sig.sign(d1, ZERO, (short)d1.length, m, ZERO);

        sig.init(key, Signature.MODE_VERIFY);
        ok = sig.verify(d1, ZERO, (short)d1.length, m, ZERO, (short)16);

        sig.init(key, Signature.MODE_SIGN);
        sig.sign(d2, ZERO, (short)d2.length, m, ZERO);

        sig.init(key, Signature.MODE_VERIFY);
        ok = sig.verify(d2, ZERO, (short)d2.length, m, ZERO, (short)16);

        sig.init(key, Signature.MODE_SIGN);
        sig.sign(d3, ZERO, (short)d3.length, m, ZERO);

        sig.init(key, Signature.MODE_VERIFY);
        ok = sig.verify(d3, ZERO, (short)d3.length, m, ZERO, (short)16);

        sig.init(key, Signature.MODE_SIGN);
        sig.sign(d4, ZERO, (short)d4.length, m, ZERO);

        sig.init(key, Signature.MODE_VERIFY);
        ok = sig.verify(d4, ZERO, (short)d4.length, m, ZERO, (short)16);


    }
*/
}
