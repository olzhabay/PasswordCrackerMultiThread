package PasswordCracker;
import org.testng.annotations.Test;

import java.util.concurrent.ExecutionException;

import static org.testng.AssertJUnit.assertEquals;
import static org.testng.internal.junit.ArrayAsserts.assertArrayEquals;

class PasswordCrackerTaskTest extends PasswordCrackerTask{

    public PasswordCrackerTaskTest() {
        super();
    }

    public PasswordCrackerTaskTest(int taskId, boolean isEarlyTermination, PasswordCrackerConsts consts, PasswordFuture passwordFuture) {
        super(taskId, isEarlyTermination, consts, passwordFuture);
    }

    @Test
    public void testFindPasswordInRange() throws ExecutionException, InterruptedException {
        PasswordFuture passwordFuture = new PasswordFuture();
        PasswordCrackerConsts consts = new PasswordCrackerConsts(1, 6, "c4b9942f2886cd34fce932f279000ef3");
        new PasswordCrackerTaskTest(0, true,  consts, passwordFuture);
        String password = findPasswordInRange(64250866, 64250900, consts.getEncryptedPassword());
        assertEquals("Output must be 1294ab", "1294ab", password);
    }

    @Test
    public void testEncryption() {
        assertEquals("Output: ", encrypt("1294ab", getMessageDigest()), "c4b9942f2886cd34fce932f279000ef3");
        assertEquals("Output: ", encrypt("2nowbv", getMessageDigest()), "f92f8fa7fd6a5fa45d53227ffec0d6ac");
    }

    @Test
    public static void testTransformation() {
        PasswordFuture passwordFuture = new PasswordFuture();
        PasswordCrackerConsts consts = new PasswordCrackerConsts(1, 6, "c4b9942f2886cd34fce932f279000ef3");
        new PasswordCrackerTaskTest(0, true,  consts, passwordFuture);
        int[] array = new int[consts.getPasswordLength()];

        transformDecToBase36(13007, array);
        assertArrayEquals("Output: " , new int[]{0, 0, 0, 10, 1, 11}, array);

        transformDecToBase36(64250867, array);
        assertArrayEquals("Output: ", new int[]{1, 2, 9, 4, 10, 11}, array);

        transformDecToBase36(623714257, array);
        assertArrayEquals("Output: ", new int[]{10, 11, 12, 13, 0, 1}, array);
    }
}
