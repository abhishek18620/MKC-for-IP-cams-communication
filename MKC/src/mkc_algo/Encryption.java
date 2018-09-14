package mkc_algo;

//import java.util.Arrays;
import java.util.Scanner;

public class Encryption {


	static StringBuffer txt = new StringBuffer();
	static StringBuffer enc_txt = new StringBuffer();
	static StringBuffer dec_txt = new StringBuffer();
	
	static int len = txt.length();
	static int start = 0, count = 0, n = 0, r = 0, k = 8;
	static String s = "";

	static int ch_map[] = new int[] { 0x0905, 0x0906, 0x0907, 0x0908, 0x0909, 0x090a, 0x090b, 0x090c };
	static int chno[] = new int[] { 0x0966, 0x0967, 0x0968, 0x0969, 0x096a, 0x096b, 0x096c, 0x096d, 0x09e, 0x09f };
	static int quo[] = new int[len];

	private static Scanner sc;

	public static void enc(StringBuffer txt) {
		
		while (start < len) {
			n = Character.codePointAt(txt, start);
			r = n % k;
			quo[start] = n / k;
			enc_txt.appendCodePoint(ch_map[r]);
			start++;
		}

		System.out.println(enc_txt);
		start = 0;
		len = enc_txt.length();

		while (start < (len-1)) {

			while (enc_txt.charAt(start) == enc_txt.charAt(start + 1)) {
				count++;
				start++;
				System.out.println(enc_txt.charAt(start));
				if (start==(len-1)){
					break;
				}
			}
			
			if (count >= 1) {
				start -= count;
				StringBuffer s1 = new StringBuffer();
				s1.appendCodePoint(chno[count+1]);
				s = s1.toString();
				enc_txt.replace(start + 1, (start + count + 1), s);
			}
			
			start += count;
			start++;
			count = 0;
			
		}

		//dec (enc_txt);
		System.out.println("The Encrypted text is: " + enc_txt);
	}
	
	/*
	public static void dec (StringBuffer enc_txt) {
														//Need to write the decryption code.
		start = 0;
		len = enc_txt.length();
		while (start<len) {
			if (Arrays.asList(chno).contains(enc_txt.charAt(start))) {
				
			}
		}
		
	}
*/
	public static void main(String[] args) {

		sc = new Scanner(System.in);
		System.out.println("Enter the text");
		txt.append(sc.nextLine());
		enc(txt);

	}

}