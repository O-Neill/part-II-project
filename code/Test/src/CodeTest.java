import java.util.Arrays;


public class CodeTest {
	public static void main(String[] args) {
		byte val = (byte)0xCF;
		System.out.println(Integer.toBinaryString(val));
		val >>= (byte)7;
		System.out.println(Integer.toBinaryString(val));
		val = (byte)(val & 1);
		System.out.println(Integer.toBinaryString(val));
		
		if (val == (byte)1) {
			System.out.println(Integer.toBinaryString(val));
		}
		
		
	}
}
