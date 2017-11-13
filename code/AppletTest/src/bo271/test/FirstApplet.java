/**
 * 
 */
package bo271.test;

import javacard.framework.*;
import javacardx.annotations.*;
//import static bo271.test.FirstAppletStrings.*;

/**
 * Applet class
 * 
 * @author <user>
 */
@StringPool(value = {
	    @StringDef(name = "Package", value = "bo271.test"),
	    @StringDef(name = "AppletName", value = "FirstApplet")},
	    // Insert your strings here 
	name = "FirstAppletStrings")
public class FirstApplet extends Applet {
	
	// Return length. This is the min possible return length.
	private static short GET_BALANCE_RESPONSE_SZ = 2;

	// Install must directly or indirectly call register()
    /**
     * Installs this applet.
     * 
     * @param bArray
     *            the array containing installation parameters
     * @param bOffset
     *            the starting offset in bArray
     * @param bLength
     *            the length in bytes of the parameter data in bArray
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new FirstApplet();
    }

    /**
     * Only this class's install method should create the applet object.
     */
    protected FirstApplet() {
    	super();
        register();
    }

    // Much of this code originally copied from JC SDK docs. (APDU section)
    /**
     * Processes an incoming APDU.
     * 
     * @see APDU
     * @param apdu
     *            the incoming APDU
     */
    @Override
    public void process(APDU apdu) {
    	// Populate buffer with the first header bytes [CLA, INS, P1, P2]
    	byte[] buffer = apdu.getBuffer();
		byte cla = buffer[ISO7816.OFFSET_CLA];
		byte ins = buffer[ISO7816.OFFSET_INS];
		if (ins != 0x30)
			ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
		if (cla != 0x80)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		short bytesLeft = (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF);
		if (bytesLeft != 0) ISOException.throwIt( ISO7816.SW_WRONG_LENGTH );
		// construct the reply APDU. (Placeholder, returns [1,2,3] instead of something stored on file)
		short le = apdu.setOutgoing();
		if (le < GET_BALANCE_RESPONSE_SZ) ISOException.throwIt( ISO7816.SW_WRONG_LENGTH );
		
		// Either send using setOutgoing(), setOutgoingLength() & sendBytes(), or just setOutgoingAndSend().
		// Should go via setOutgoing() to check expected return length.
		
		// TODO: Return something stored on card
		// build response data in apdu.buffer[ 0.. outCount-1 ];
		buffer[0] = (byte)1; buffer[1] = (byte)2; buffer[3] = (byte)3;
		apdu.setOutgoingAndSend((short) 0, (short) 3); 
		apdu.sendBytes ( (short)0 , (short)3 );
		// returns good complete status 90 00
    }
    
    
    // Optional. Called to notify applet it is selected for APDU processing.
 	// True indicates it's ready to process incoming APDUs. May need to initialise session.
 	@Override
 	public boolean select() {
 		return true;
 	}
 	
 	// Optional. May cleanup session.
 	@Override
 	public void deselect() {
 		return;
 	}
}
