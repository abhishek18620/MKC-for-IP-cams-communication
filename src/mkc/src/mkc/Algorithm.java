package mkc;

import org.apache.commons.lang3.ArrayUtils;
import java.util.Scanner;

public class Algorithm {

    static int ch_map[] = new int[]{0x0905, 0x0906, 0x0907, 0x0908, 0x0909, 0x090a, 0x090b, 0x090c};
    static int chno[] = new int[]{0x0966, 0x0967, 0x0968, 0x0969, 0x096a, 0x096b, 0x096c, 0x096d, 0x09e, 0x09f};

    private static Scanner sc;

    public static void enc(StringBuilder txt) {

        int start = 0, count = 0, n = 0, r = 0, k = 8;
        String s = "";
        StringBuilder enc_txt = new StringBuilder();
        int len = txt.length();
        int quo[] = new int[len];

        while (start < len) {
            n = Character.codePointAt(txt, start);
            r = n % k;
            quo[start] = n / k;
            enc_txt.appendCodePoint(ch_map[r]);
            start++;
        }

        start = 0;
        len = enc_txt.length();

        while (start < (len - 1)) {

            while (enc_txt.charAt(start) == enc_txt.charAt(start + 1)) {
                count++;
                start++;
                if (start == (len - 1)) {
                    break;
                }
            }

            if (count >= 1) {
                start -= count;
                StringBuilder s1 = new StringBuilder();
                s1.appendCodePoint(chno[count + 1]);
                s = s1.toString();
                enc_txt.replace(start + 1, (start + count + 1), s);
            }

            start += count;
            start++;
            count = 0;

        }

        System.out.println("The Encrypted text is: " + enc_txt);
        dec(enc_txt, quo, k);
    }

    public static void dec(StringBuilder enc_txt, int[] quo, int k) {
        StringBuilder dec_txt = new StringBuilder();
        dec_txt.append("");
        int index = 0, start = 0, u;
        String s = "";
        int len = enc_txt.length();
        char ch;

        while (start < len) {

            for (int i = 0; i < chno.length; i++) {
                if ((Character.codePointAt(enc_txt, start)) == chno[i]) {

                    index = ArrayUtils.indexOf(chno, Character.codePointAt(enc_txt, start));
                    ch = enc_txt.charAt(start - 1);
                    s += ch;
                    s += ch;

                    for (int j = 1; j < index; j++, start++) {
                        enc_txt.replace(start - 1, start + 1, s);
                    }
                    s = "";
                    break;
                }
            }
            start++;
        }

        start = 0;

        while (start < len) {
            u = quo[start] * k + ArrayUtils.indexOf(ch_map, Character.codePointAt(enc_txt, start));
            dec_txt.append(Character.toChars(u));
            start++;
        }
        System.out.println("The decrypted text is: " + dec_txt);
    }

    public static void main(String[] args) {

        StringBuilder txt = new StringBuilder();
        sc = new Scanner(System.in);
        System.out.println("Enter the text");
        txt.append(sc.nextLine());
        enc(txt);

    }

}