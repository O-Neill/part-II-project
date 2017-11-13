package uk.ac.cam.bo271.applets.hello;


import javacard.framework.*;

public class HelloWorld extends Applet {

	// Return length. This is the min possible return length.
	private static short GET_BALANCE_RESPONSE_SZ = 3;

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
        HelloWorld applet = new HelloWorld();
				applet.register();
    }

    // Much of this code originally copied from JC SDK docs. (APDU section)
    @Override
    public void process(APDU apdu) {
    	// Populate buffer with the first header bytes [CLA, INS, P1, P2]
    byte[] buffer = apdu.getBuffer();

		byte cla = buffer[ISO7816.OFFSET_CLA];
		byte ins = buffer[ISO7816.OFFSET_INS];
		//if (ins != 0x30)
		//	ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);

		switch (cla) {
			case (byte)0x00: return;

			case (byte)0x80:
				// Assume the command has no incoming data. Ignore/don't check Lc.

				// Either send using setOutgoing(), setOutgoingLength() & sendBytes(), or just setOutgoingAndSend().
				// go via setOutgoing() to check expected return length.
				short le = apdu.setOutgoing();
				if (le < GET_BALANCE_RESPONSE_SZ) ISOException.throwIt( ISO7816.SW_WRONG_LENGTH );
				apdu.setOutgoingLength( (short)3 );
				buffer[0] = (byte) cla;
				buffer[1] = (byte) ins;
				buffer[2] = (byte) 0;
				apdu.sendBytes((short)0, (short)3);
				// TODO: return something stored on card.
				break;

			default: ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}
		return;

		//apdu.sendBytes ( (short)0 , (short)3 );
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
