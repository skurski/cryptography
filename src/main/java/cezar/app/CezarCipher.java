package cezar.app;

import cezar.decrypt.CezarDecryption;
import cezar.encrypt.CezarEncryption;
import cezar.util.StringUtil;

/**
 * Present how encryption and decryption works.
 */
public class CezarCipher {

    public static void main(String[] args) {
        // Get file
        String textToEncrypt = StringUtil.read("plaintext.txt");
        int SHIFT_BY = 5;

        /** ENCRYPTION **/
        CezarEncryption encryption = new CezarEncryption();
        String securedText = encryption.encrypt(textToEncrypt, SHIFT_BY);

        System.out.println("Plain text: " + textToEncrypt);
        System.out.println("Encrypted text: " + securedText);

        /** DECRYPTION **/
        CezarDecryption decryption = new CezarDecryption();
        int shiftedBy = decryption.findShift(securedText, "popular.txt");
        System.out.println("Shift: " + shiftedBy);
        System.out.println("Decrypted msg: " + decryption.decrypt(securedText, shiftedBy));

        // TEST LeHack
        System.out.println("LeHack probable shift: " +
                decryption.findShift(StringUtil.read("lehack_cipher.txt"), "long-english-text.txt"));

        // TEST another cipher
        System.out.println("Second probable shift: " +
                decryption.findShift(StringUtil.read("second_cipher.txt"), "long-english-text.txt"));
    }
}
