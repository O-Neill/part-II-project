package bo271.first;

import javacard.framework.*;

public class FirstApp extends Applet{
	
	@Override
	public void process(APDU arg0) throws ISOException {
		// TODO Auto-generated method stub
		
	}
	
	@Override
	public boolean select() {
		
		return true;
	}
	
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		// Allocate applet here. Best to do so early in case card runs out of memory.
		new FirstApp();
	}
}
