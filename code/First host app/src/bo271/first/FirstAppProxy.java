package bo271.first;

import opencard.core.service.CardServiceException;
import opencard.core.service.CardServiceInvalidCredentialException;
import opencard.core.service.CardServiceInvalidParameterException;
import opencard.core.service.CardServiceOperationFailedException;
import opencard.core.service.CardServiceScheduler;
import opencard.core.service.SmartCard;
import opencard.core.terminal.CardTerminalException;
import opencard.core.terminal.CommandAPDU;
import opencard.core.terminal.ResponseAPDU;
import opencard.opt.applet.AppletID;
import opencard.opt.applet.AppletProxy;
import opencard.opt.service.CardServiceUnexpectedResponseException;

// Modified from verison on Oracle website

public class FirstAppProxy extends AppletProxy {
	
	/** Application identifier of the basic applet */
    // First 5 bytes - RID (unique Id of application provider. Should be fine - application scope limited.
    // 0-11 bytes proprietary application ID extension to maintain uniqueness.

	// Applet ID of gpshell sample applet.
    private static final AppletID MY_CARD_AID = new AppletID(new byte[] {  
    									(byte)0xd0,
                                        (byte)0xd1,
                                        (byte)0xd2,
                                        (byte)0xd3,
                                        (byte)0xd4,
                                        (byte)0xd5,
                                        (byte)0x01});
    private CommandAPDU requestAPDU = new CommandAPDU(14);
    
    // APDU definitions
    final static byte MyAPPLET_CLA = (byte)0x80; // Command class. 80 means no secure messaging, no further commands in chain.
    final static byte GET_DATA_INS = (byte) 0x30; // Instruction code.
    protected final static int OK = 0x9000; //Standard 'success' response APDU trailer
    
    
    /**
     * Create a MyCardProxy instance.
     *
     * @param scheduler The Scheduler from which channels 
     * have to be obtained.
     * @param card      The SmartCard object to which this 
     * service belongs.
     * @param blocking  Currently not used.
     *
     * @throws opencard.core.service.CardServiceException
     *         Thrown when instantiation fails.
     */
    protected void initialize(CardServiceScheduler scheduler, SmartCard card, boolean blocking) 
			throws CardServiceException {
		super.initialize(MY_CARD_AID, scheduler, card, blocking);
		try {
			// Allocate the card channel. This gives us 
			// exclusive access to the card until we release the 
			// channel.
			allocateCardChannel();
			
			// TODO: Get any required initial Card State via APDUs.
			
		
		} finally {
			releaseCardChannel();
		}
    }
    
    
    /**
     * Gets the balance.
     * @return The balance.
     */
    public String getContent() 
        throws CardServiceInvalidCredentialException,
               CardServiceOperationFailedException,
               CardServiceInvalidParameterException,
               CardServiceUnexpectedResponseException,
               CardServiceException,
               CardTerminalException {
        try {
            allocateCardChannel();

            // Set up the command APDU and send it to the card.
            requestAPDU.setLength(0);
            requestAPDU.append(MyAPPLET_CLA); // Class
            requestAPDU.append(GET_DATA_INS); // Instr'n
            requestAPDU.append((byte) 0x00); // P1 (param)
            requestAPDU.append((byte) 0x00); // P2 (param)
            requestAPDU.append((byte) 0x00); // Lc (number of bytes of command data to follow this field)
            requestAPDU.append((byte) 0x00); // Le (Max response bytes accepted)

            // Send command APDU and check the response.
            ResponseAPDU response = sendCommandAPDU(getCardChannel(), MY_CARD_AID, requestAPDU);
            switch (response.sw() & 0xFFFF) {
                case OK :
                    return new String(response.data());
                default :
                    throw new CardServiceUnexpectedResponseException("RC=" + response.sw());
            }
        } finally {
            releaseCardChannel();
        }
    }
}
