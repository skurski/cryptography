package cezar.decrypt;

import cezar.encrypt.CezarEncryption;
import cezar.util.StringUtil;

import java.util.HashMap;
import java.util.Map;

public class CezarDecryption {

    private static char[] alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".toLowerCase().toCharArray();
    private static Map<Character, Integer> alphabetIndex = new HashMap<>();
    static {
        for (int i = 0; i< alphabet.length; i++) {
            alphabetIndex.put(alphabet[i], i);
        }
    }
    private static int CHARS_MAX = alphabet.length - 1;

    /**
     * Return shift value.
     */
    public int findShift(String encryptedText, String pathToLangPopularText) {
        String popularText = StringUtil.read(pathToLangPopularText);
        Map<Character, Integer> charsInEncrypted = countOccurency(encryptedText);
        Map<Character, Integer> charsInPopular = countOccurency(popularText);
        return comparison(charsInEncrypted, charsInPopular);
    }

    private Map<Character, Integer> countOccurency(String text) {
        Map<Character, Integer> words = new HashMap<>();
        char[] chars = text.toCharArray();

        for (int i=0; i<chars.length; i++) {
            Integer value = words.get(Character.toLowerCase(chars[i]));
            if (value == null) {
                value = new Integer(1);
            } else {
                value++;
            }
            if (!Character.isWhitespace(chars[i]) && Character.isAlphabetic(chars[i])) {
                words.put(Character.toLowerCase(chars[i]), value);
            }
        }

        return words;
    }

    private int comparison(Map<Character, Integer> encryptedMap, Map<Character, Integer> popularMap) {
        char maxInEncrypt = getCharIndex(encryptedMap);
        System.out.println("Most popular char in encrypted text: " + maxInEncrypt);

        char maxInPopular = getCharIndex(popularMap);
        System.out.println("Most popular char in given language: "+ maxInPopular);

        int actual = alphabetIndex.get(maxInEncrypt);
        int popular = alphabetIndex.get(maxInPopular);

        if (popular <= actual) {
            return actual - popular;
        }

        return (CHARS_MAX - popular) +  actual;
    }

    private char getCharIndex(Map<Character, Integer> chars) {
        Map<Character, Integer> max = new HashMap<>();
        Integer value = 0;
        Character charr = ' ';

        for (Map.Entry<Character, Integer> entry : chars.entrySet()) {
            if (value < entry.getValue()) {
                value = entry.getValue();
                charr = entry.getKey();
            }
        }

        return charr;
    }

    public String decrypt(String encryptedText, int shift) {
        char[] chars = encryptedText.toLowerCase().toCharArray();
        StringBuffer output = new StringBuffer();

        for (int i=0; i<chars.length; i++) {
            if (Character.isAlphabetic(chars[i])) {
                int index = alphabetIndex.get(chars[i]);
                index = calculateIndex(index, shift);
                output.append(alphabet[index]);
                continue;
            }
            output.append(chars[i]);
        }

        return output.toString();
    }

    private int calculateIndex(int index, int shift) {
        if (index - shift < 0) {
            shift = shift - index;
            return CHARS_MAX - shift;
        }
        return index - shift;
    }
}
