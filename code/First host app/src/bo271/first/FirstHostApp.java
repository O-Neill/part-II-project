package bo271.first;

import opencard.core.event.CardTerminalEvent;
import opencard.core.event.CTListener;
import opencard.core.event.EventGenerator;
import opencard.core.service.CardRequest;
import opencard.core.service.SmartCard;
import opencard.core.terminal.CardID;
import opencard.core.terminal.CardTerminalException;
import opencard.core.util.HexString;

public class FirstHostApp implements CTListener {
    private static Object monitor = "synchronization monitor";
	private SmartCard card;
	FirstAppProxy appProxy;
	
	public static void main(String[] args) throws InterruptedException {
		try {
			System.out.println("Enter");
		    // Initialize OCF
			System.out.println("Enter");
		    SmartCard.start();
		    
		    for (int i = 0; i < 100; i++)
		    	System.out.println("started framework");
		    
		    // Wait for a smart card
		    CardRequest cr = new CardRequest(CardRequest.NEWCARD, null,
		                                     null);
		    
		    SmartCard myCard = SmartCard.waitForCard(cr);
		    System.out.println("got card");
		    if (myCard != null) {
		    	CardID cardID = myCard.getCardID();
		    	StringBuffer sb = new StringBuffer("Obtained the following CardID:\n\n");
		    	byte [] atr = cardID.getATR ();
		    	sb.append (HexString.hexify (atr) ).append ('\n');
		    	System.out.println(sb);
		    }
		    
		    System.out.println("Got card");

		    // Main client work is done here...
		    
		} catch (Exception e){
		    // Handle exception
		} finally {
		    try {
		        // Shut down OCF
		        SmartCard.shutdown();
		    } catch (Exception e) {
		        e.printStackTrace();
		    }
		}
		
		
		/*
		
		String dotPropStr = OpenCardConstants.OPENCARD_DOTPROPERTIES;
		String propStr = OpenCardConstants.OPENCARD_PROPERTIES;
		SystemAccess sys = SystemAccess.getSystemAccess();
		String[] locations = {
				sys.getProperty("java.home", "") + File.separator + "lib"
						+ File.separator + propStr,
				sys.getProperty("user.home", "") + File.separator
						+ dotPropStr,
				sys.getProperty("user.dir", "") + File.separator + propStr,
				sys.getProperty("user.dir", "") + File.separator
						+ dotPropStr };
		
		for (String loc : locations) {
			System.out.println(loc);
		}
		
		
		
		System.out.println("Hello world");
		FirstHostApp app = new FirstHostApp();
		synchronized(monitor) {
			monitor.wait();
		}
		*/
	}
	
	public FirstHostApp() {
		System.out.println("Enter constructor");
		try {
            // Initialise the framework
            SmartCard.start ();
            // Register this as a Card Terminal Event Listener
            EventGenerator.getGenerator().addCTListener(this);
            System.out.println("Leave constructor");
        } catch (Exception e) {
        	e.printStackTrace();
        }
	}

	/**
     * Gets invoked if a card is inserted.
     */
    public void cardInserted (CardTerminalEvent ctEvent) {
    	System.out.println ("card inserted");
    
	    try {
	        // Get a SmartCard object
	    	CardRequest req = new CardRequest(CardRequest.ANYCARD, null, null);
	        card = SmartCard.getSmartCard(ctEvent, req);
	        
	        // Get and print card ID
	        CardID cardID = card.getCardID();
	        StringBuffer sb = new StringBuffer("Obtained the following CardID:\n");
	        byte[] atr = cardID.getATR();
	        sb.append(HexString.hexify(atr)).append('\n');
	        System.out.println(sb);
	        
	        // Get the card proxy instance.
	        appProxy = (FirstAppProxy) card.getCardService(FirstAppProxy.class, true);
	        
	        System.out.print(appProxy.getContent());
	        
	    } catch (Exception e) {
	        e.printStackTrace();
	    }
	    synchronized (monitor) {
	    	
	    	monitor.notifyAll();
    	}
    } // cardInserted


    /**
     * Gets invoked if a card is removed.
     */
    public synchronized void cardRemoved (CardTerminalEvent ctEvent) {
    	synchronized (monitor) {
    		System.out.println ("card removed");
        	card = null;
        	appProxy = null;
        	try {
				SmartCard.shutdown();
			} catch (CardTerminalException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
        	monitor.notifyAll();
    	}
    } // cardRemoved


    /**
     * Get balance from the smart card.
     */
    public int getContent() {
        try {
            // Get mutex to prevent other Card Services from modifying 
            // data. Delegate the call to the applet proxy.
            card.beginMutex();
            return Integer.parseInt(appProxy.getContent());
        } catch (Throwable e) {
            return 0;
        } finally {
            // End mutual exclusion
            card.endMutex();
        }
    }
    
} // InsertRemoveCard