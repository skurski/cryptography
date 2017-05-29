package hacking.bruteforce;

/**
 * Brute force attack algorithm.
 * <p>
 * TDD development approach - use cases in tests.
 */
public class BruteForceAttack {

    private static final String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    private String password = null;

    private String result = null;

    private int depth = 0;

    /**
     * Decryption method.
     *
     * @return decrypted (plain) text
     */
    public void decrypt() {
        run(new char[alphabet.length()], 0, depth);
    }

    private void run(char[] combinations, int index, int max) {
        for (int i = 0; i < alphabet.length() - 1; i++) {
            combinations[index] = alphabet.charAt(i);

            if (index == max - 1) {
                String possiblePass = prepareString(combinations);
                if (password.equals(possiblePass)) {
                    System.out.println("Password result: " + possiblePass);
                    result = possiblePass;
                }
            } else {
                run(combinations, index + 1, max);
            }
        }
    }

    private String prepareString(char[] characters) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < characters.length; i++) {
            if (characters[i] == '\u0000') {
                break;
            }
            sb.append(characters[i]);
        }
        return sb.toString();
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public void setDepth(int depth) {
        this.depth = depth;
    }

    public String getResult() {
        return result;
    }
}
