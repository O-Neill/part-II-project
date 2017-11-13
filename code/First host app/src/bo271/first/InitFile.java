package bo271.first;

import opencard.core.service.SmartCard;
import opencard.core.service.CardRequest;
import opencard.opt.iso.fs.FileAccessCardService;
import opencard.opt.iso.fs.CardFile;

// This class modifies the contents of a Java Card. This is usually done during initialisation.
public class InitFile {
	public static void main(String[] args) {
		System.out.println("initializing file...");
		try {
			SmartCard.start();
			
			// wait for a smartcard with file access support
			CardRequest cr = new CardRequest(CardRequest.NEWCARD, null, FileAccessCardService.class);
			SmartCard   sc = SmartCard.waitForCard(cr);
			FileAccessCardService facs = (FileAccessCardService)
			sc.getCardService(FileAccessCardService.class, true);
			CardFile root = new CardFile(facs);
			CardFile file = new CardFile(root, ":c009");
			
			// here, we will write data to the smart card. Assume some string was passed in as an argument.
			// e.g. java InitFile "Klaus Mustermann:klaus@banana.com"
			String entry = args[0].replace(':', '\n');
			byte[] bytes = entry.getBytes();
			int   length = bytes.length;
			
			// If array is shorter than file, pad with 0. If longer, truncate.
			byte[] data  = new byte [file.getLength()];
			if (data.length < length)
			length = data.length;
			System.arraycopy(bytes, 0, data, 0, length);
			
			// write the data to the file
			facs.write(file.getPath(), 0, data);
			System.out.println(entry);
			
		} catch(Exception e) {
			e.printStackTrace(System.err);
		} finally { // even in case of an error...
			try {
				SmartCard.shutdown();
			} catch(Exception e) {
				e.printStackTrace(System.err);
			}
		}
		System.exit(0);
	}
}