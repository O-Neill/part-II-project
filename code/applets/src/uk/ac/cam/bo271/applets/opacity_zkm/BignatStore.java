package uk.ac.cam.bo271.applets.opacity_zkm;
import javacard.framework.*;

public class BignatStore {
    public static final short Bignat_length = (short)32;

    // Auxiliary Bignat instances to be used during function execution.
    public static Bignat temp_val_1;
    public static Bignat temp_val_2;
    public static Bignat temp_val_3;
    public static Bignat temp_val_4;
    public static Bignat temp_val_5;
    public static Bignat temp_val_6;
    public static Bignat temp_val_7;
    public static Bignat temp_val_8;

    // Max Bignat value.
    // TODO: Try to get rid of this.
    public static Bignat max_val;

    public static void init(Bignat_Helper bnh) {
        temp_val_1 = new Bignat((short)32, JCSystem.CLEAR_ON_RESET, bnh);
        temp_val_2 = new Bignat((short)32, JCSystem.CLEAR_ON_RESET, bnh);
        temp_val_3 = new Bignat((short)32, JCSystem.CLEAR_ON_RESET, bnh);
        temp_val_4 = new Bignat((short)32, JCSystem.CLEAR_ON_RESET, bnh);
        temp_val_5 = new Bignat((short)32, JCSystem.CLEAR_ON_RESET, bnh);
        temp_val_6 = new Bignat((short)32, JCSystem.CLEAR_ON_RESET, bnh);
        temp_val_7 = new Bignat((short)32, JCSystem.CLEAR_ON_RESET, bnh);
        temp_val_8 = new Bignat((short)32, JCSystem.CLEAR_ON_RESET, bnh);

        max_val = new Bignat((short)32, JCSystem.CLEAR_ON_RESET, bnh);
        byte[] max_arr = max_val.as_byte_array();
        Util.arrayFillNonAtomic(max_arr, (short)0, (short)32, (byte)0xFF);
    }
}
