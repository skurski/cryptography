package hacking.bruteforce;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

/**
 * Tests for brute force algorithm implementation (TDD).
 */
public class BruteForceAttackTest {

    private BruteForceAttack bruteForceAttack = new BruteForceAttack();

    @Before
    public void setUp() throws Exception {

    }

    @Test
    public void decryptTest_shouldReturnA() throws Exception {
        String pass = "A";
        bruteForceAttack.setPassword(pass);
        bruteForceAttack.setDepth(1);
        bruteForceAttack.decrypt();
        Assert.assertEquals(pass, bruteForceAttack.getResult());
    }

    @Test
    public void decryptTest_shouldFindOneLetterPassword() throws Exception {
        String pass = "X";
        bruteForceAttack.setPassword(pass);
        bruteForceAttack.setDepth(1);
        bruteForceAttack.decrypt();
        Assert.assertEquals(pass, bruteForceAttack.getResult());
    }

    @Test
    public void decryptTest_shouldFindTwoLetterPassword() throws Exception {
        String pass = "g7";
        bruteForceAttack.setPassword(pass);
        bruteForceAttack.setDepth(2);
        bruteForceAttack.decrypt();
        Assert.assertEquals(pass, bruteForceAttack.getResult());
    }

    @Test
    public void decryptTest_shouldFindThreeLetterPassword() throws Exception {
        String pass = "g7F";
        bruteForceAttack.setPassword(pass);
        bruteForceAttack.setDepth(3);
        bruteForceAttack.decrypt();
        Assert.assertEquals(pass, bruteForceAttack.getResult());
    }
}
