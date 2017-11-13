package uk.ac.cam.bo271.applets.challengeresponse;

import javacard.framework.*;

public class ChallengeResponse extends Applet {

	private static byte[] byteArray;

	// Install must directly or indirectly call register()
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        ChallengeResponse applet = new ChallengeResponse();
		applet.register();
		byteArray = new byte[5];
		byteArray[0] = 0x68;
		byteArray[1] = 0x65;
		byteArray[2] = 0x6C;
		byteArray[3] = 0x6C;
		byteArray[4] = 0x6F;
		// TODO: Initialise byte array
    }

	private void response(APDU apdu, byte[] data) {
		byte[] buffer = apdu.getBuffer();
		short le = apdu.setOutgoing();
		if (le < data.length)
			ISOException.throwIt( ISO7816.SW_WRONG_LENGTH );
		apdu.setOutgoingLength( (short)data.length );
		Util.arrayCopy(data, (short)0, buffer, (short)0, (short)data.length);
		apdu.sendBytes((short)0, (short) data.length);
	}

	private void sendContents(APDU apdu) {
		response(apdu, byteArray);
	}

	// Resize the array by deleting old object, creating new one.
	void updateBuffer(byte requiredSize){
     	try{
         	if(byteArray != null && byteArray.length == requiredSize){
             	//we already have a buffer of required size
             	return;
         	}

	        JCSystem.beginTransaction();
	        byte[] oldBuffer = byteArray;
	        byteArray = new byte[requiredSize];
	        if (oldBuffer != null)
	            JCSystem.requestObjectDeletion();
	        JCSystem.commitTransaction();
     	} catch(Exception e){
         	JCSystem.abortTransaction();
     	}
	}

	// Could abstract into method for extracting apdu data.
	private void setArray(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		byte Lc = buffer[ISO7816.OFFSET_LC];
		updateBuffer((byte)Lc);
		Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, byteArray, (short)0, Lc);
	}

    // Much of this code originally copied from JC SDK docs. (APDU section)
    @Override
    public void process(APDU apdu) {
    	// Populate buffer with the first header bytes [CLA, INS, P1, P2]
        byte[] buffer = apdu.getBuffer();

		byte cla = buffer[ISO7816.OFFSET_CLA];
		byte ins = buffer[ISO7816.OFFSET_INS];
		//if (ins != 0x30)
		//

		switch (cla) {
            case (byte)0x00: return;

			case (byte)0x80:
				break;
		}

		switch (ins) {
			case (byte) 0x30:
				setArray(apdu);
				break;

			case (byte) 0x31:
				sendContents(apdu);
				break;

			default: ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
		}
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
