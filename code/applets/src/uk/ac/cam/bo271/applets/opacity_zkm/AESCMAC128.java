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
    // NIST 800-38B standards. Generates 16B CMAC keys.
    private static byte Rb = (byte) 0x87;
    private byte[] k1;
    public byte[] k2;
    private AESKey aesKey;

    private byte[] prev_block;
    private boolean seen_data;
    Signature aesMAC;

    // TODO: Initialise and use.
    private byte[] k;
    private byte[] lastBlock;

    public AESCMAC128() {
        k = JCSystem.makeTransientByteArray((short)16, JCSystem.CLEAR_ON_DESELECT);
        k1 = JCSystem.makeTransientByteArray((short)16, JCSystem.CLEAR_ON_DESELECT);
        k2 = JCSystem.makeTransientByteArray((short)16, JCSystem.CLEAR_ON_DESELECT);
        prev_block = JCSystem.makeTransientByteArray((short)16, JCSystem.CLEAR_ON_DESELECT);
    }

    public byte[] getk2() {
        return k2;
    }
    public byte[] getk1() {
        return k1;
    }

    // TODO: Can I do this easily using Bignat?
    private static void leftShiftArray(byte[] buffer) {
        if (buffer == null) {
            ISOException.throwIt((short)0x5532);
        }
        byte carry = 0;
        byte c2 = 0;
        // Storage is big-endian, so to loop starting at the LSB, need to start
        // at the larger index.
        for (short i = (short)(buffer.length - 1); i >= 0; i--) {

            // carry msb in buffer

            // Carry value for next byte is the most significant bit of the
            // current one.

            c2 = buffer[i];
            c2 >>= 7;
            c2 = (byte)(c2 & (byte)1);


            // Left-shift, and apply the carry.
            buffer[i] <<= 1;
            buffer[i] = (byte)(buffer[i] & (byte)0xFE);

            buffer[i] += carry;


            // Update the carry to the carry value of the next byte.
            carry = c2;

        }

    }

    // Calling this method repeatedly will generate key rotations that can be
    // used as subkeys (as per the NIST 800-38B standards)
    private void subkeys(byte[] k) {
        // TODO: Check size of k = 16

        // Step 2 - if leftmost bit of L is 0, k1=L<<1 else k1=(L<<1)^Rb
        byte msb = (byte) (k[0] & (byte)0x80);  // 0 or 1 depending on msb of L

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
        Util.arrayFillNonAtomic(k, (short)0, (short)16, (byte)0x00);

        // Compute and store keys k1 and k2.
        aesKey.getKey(k, (short)0);

        Util.arrayFillNonAtomic(k1, (short)0, (short)16, (byte)0x00);
        aesMAC = Signature.getInstance(Signature.ALG_AES_MAC_128_NOPAD, false);
        aesMAC.init(aesKey, Signature.MODE_SIGN);
        aesMAC.sign(k1, (short)0, (short)16, k1, (short)0);

        subkeys(k1);

        Util.arrayCopy(k1, (short)0, k2, (short)0, (short)16);

        subkeys(k2);

        Util.arrayFillNonAtomic(prev_block, (short)0, (short)16, (byte)0x00);
        seen_data = false;

        aesMAC.init(aesKey, Signature.MODE_SIGN);

    }

    public short sign(byte[] input, short inOffset, short len, byte[] sigBuff, short sigOffset) {
        lastBlock = JCSystem.makeTransientByteArray((short)16, JCSystem.CLEAR_ON_DESELECT);
        // Number of complete blocks (minus the last one if the last is complete)
        short leadingBlocks = (short)(len/16);  // Number of blocks before last.
        short lastBlockLen = (short)(len % 16);

        boolean no_data = !seen_data && len == 0;
        // Deal with special case of no input data. Pad block with 1 followed by
        // 0s and treat as single, complete block.


        if (lastBlockLen == 0 && !no_data) {
            // Overall input is a multiple of the block length.
            // Last block will be a full block.
            leadingBlocks--;
            lastBlockLen = 16;
        }
        short leadingBlocksLen = (short)(16 * leadingBlocks);


        // TODO: Complete the last block if not complete, then feed all input
        // into update(), then return the resulting cipher value.


        // Step 4
        if (len != 0) {
            // Get last (possibly incomplete) block from sign() input
            Util.arrayCopy(input, (short)(inOffset + leadingBlocksLen), lastBlock,
                           (short)0, lastBlockLen);
        } else if (!no_data) {
            // Final input is last cached block provided to update()
            Util.arrayCopy(prev_block, (short)0, lastBlock, (short)0, (short)16);
        }
        // If no data was provided, lastBlock is a 0 block.

        if (lastBlockLen == 16) {
            // Last block takes up entire block, XOR it with k1
            for (short i = 0; i < 16; i++) {
                lastBlock[i] = (byte)(lastBlock[i] ^ k1[i]);
            }
        } else {
            // Pad last block with 1 followed by 0s and XOR with k2

            // Set the byte following the last data byte to 10000000
            lastBlock[lastBlockLen] = (byte)0x80;
            // Set all later bytes to 0.
            for (short i = (short)(lastBlockLen + 1); i < 16; i++) {
                lastBlock[i] = 0x00;
            }

            // Now XOR entire block with k2.
            for (short i = 0; i < 16; i++) {
                lastBlock[i] = (byte)(lastBlock[i] ^ k2[i]);
            }
        }

        // If the last block comes from the sign() input, update with prev_block
        if (len != 0) {

            if (leadingBlocksLen != 0) {
                // Pass the leading blocks to the cipher if there are any.
                update(input, inOffset, leadingBlocksLen);

                // Cipher the cached block (second last block).
                aesMAC.update(prev_block, (short)0, (short)16);
            }
        }

        aesMAC.sign(lastBlock, (short)0, (short)16, sigBuff, sigOffset);

        return 16;
    }

    // TODO: Cipher the second last one. The last one may be the last of the
    // message.
    public void update(byte[] input, short inOffset, short len) {

        // input should be positive multiple of block size
        if (len == 0 || (len % 16 != 0)) {
            CryptoException.throwIt(CryptoException.ILLEGAL_USE);
        }

        // If this is not the first data seen, cipher the previously seen
        // block.

        if (seen_data) {
            aesMAC.update(prev_block, (short)0, (short)16);
        }

        seen_data = true;

        short blocks = (short)(len / 16);

        // Process all but last block (it could be the last in the message in
        // which case it should be processed differently)
        for (short i = 0; i < (short)(blocks-1); i++) {

            aesMAC.update(input, (short)(inOffset + i*16), (short)16);
        }

        // Cache the last block in case it is the final one in the message.
        Util.arrayCopy(input, (short)(inOffset + len - 16), prev_block, (short)0, (short)16);
    }

    public boolean verify(byte[] input, short inOffset, short len,
                          byte[] sigBuff, short sigOffset, short sigLen) {
        if (sigLen != 16) {
            return false;
        }

        // TODO: Timing attack?
        byte[] t = JCSystem.makeTransientByteArray((short)16, JCSystem.CLEAR_ON_DESELECT);

        sign(input, inOffset, len, t, (short)0);
        return true;
    }


    public static void send(byte[] buf, short offset, short len, APDU apdu) {

        byte[] ret_buffer = apdu.getBuffer();

        short ret_len = apdu.setOutgoing();

        if (ret_len < len)
            ISOException.throwIt( ISO7816.SW_WRONG_LENGTH );

        apdu.setOutgoingLength(len);

        Util.arrayCopy(buf, offset, ret_buffer, (short)0, len);

        apdu.sendBytes((short)0, len);
    }



}
