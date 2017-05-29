package cezar.encrypt;

import java.util.HashMap;
import java.util.Map;

/**
 * Encrypt text for 26 words alphabetIndex (english).
 */
public class CezarEncryption {

    private static char[] alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".toLowerCase().toCharArray();
    private static Map<Character, Integer> alphabetIndex = new HashMap<>();
    static {
        for (int i = 0; i< alphabet.length; i++) {
            alphabetIndex.put(alphabet[i], i);
        }
    }

    private int shift = 0;
    private static int CHARS_MAX = alphabet.length - 1;

    /**
     * Iterate through plain text and shift every letter by X places.
     * @param text
     * @return String encrypted text
     */
    public String encrypt(String text, int shift) {
        this.shift = shift;
        char[] chars = text.toLowerCase().toCharArray();
        StringBuffer output = new StringBuffer();

        for (int i=0; i<chars.length; i++) {
            if (Character.isAlphabetic(chars[i])) {
                int index = alphabetIndex.get(chars[i]);
                // index from 0 to 25
                index = calculateIndex(index);
                output.append(alphabet[index]);
                continue;
            }
            output.append(chars[i]);
        }

        return output.toString();
    }

    private int calculateIndex(int index) {
        if (index + shift > CHARS_MAX) {
            return (index + shift) - CHARS_MAX;
        }
        return index + shift;
    }
}
