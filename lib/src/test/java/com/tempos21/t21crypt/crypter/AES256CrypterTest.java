package com.tempos21.t21crypt.crypter;

import com.tempos21.t21crypt.exception.CrypterException;
import com.tempos21.t21crypt.exception.DecrypterException;
import com.tempos21.t21crypt.exception.EncrypterException;

import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class AES256CrypterTest {

    private static final String KEY = "validKey";

    private static final String WHAT_I_WANT_TO_CRYPT = "whatIWantToCrypt1234";

    private static final String WHAT_I_WANT_TO_DECRYPT = "rAvceqEKRR3uG7jltp7EccfMobmipUgvp142pnmQB2g=";

    private static final String INPUT_1 = "";

    private static final String INPUT_2 = "InP47$%&#@\"'?¿ª";

    private static final String INPUT_3 = "verylonginputverylonginputverylonginputverylonginputverylonginputverylonginputverylong"
            + "inputverylonginputverylonginputverylonginputverylonginputverylonginputverylonginputverylonginputverylonginputveryl"
            + "onginputverylonginputverylonginputverylonginputverylonginputverylonginputverylonginputverylonginputverylonginputve"
            + "rylonginputverylonginputverylonginputverylonginputverylonginputverylonginputverylonginputverylonginputverylonginpu"
            + "tverylonginputverylonginputverylonginputverylonginputverylonginputverylonginputverylonginputverylonginputverylongi"
            + "nputverylonginputverylonginputverylonginputverylonginputverylonginputverylonginputverylonginputverylonginputverylo"
            + "nginputverylonginputverylonginputverylonginputverylonginputverylonginputverylonginputverylonginputverylonginput";

    private AES256Crypter crypter;

    @Before
    public void setUp() throws Exception {
        crypter = AES256Crypter.getInstance(KEY);

    }

    @Test(expected = CrypterException.class)
    public void shouldCrypterReturnEncrypterExceptionWhenNullKey() throws Exception {
        AES256Crypter.getInstance(null);
    }

    @Test(expected = EncrypterException.class)
    public void shouldEncryptReturnEncrypterExceptionWhenNullText() throws Exception {
        crypter.encrypt(null);
    }

    @Test
    public void shouldEncryptReturnNotNull() throws Exception {
        String encryptedString = crypter.encrypt(WHAT_I_WANT_TO_CRYPT);

        assertNotNull(encryptedString);
    }

    @Test
    public void shouldEncryptReturnString() throws Exception {
        Object encryptedString = crypter.encrypt(WHAT_I_WANT_TO_CRYPT);

        assertTrue(encryptedString instanceof String);
    }

    @Test
    public void shouldEncryptReturnStringWhenEmptyInput() throws Exception {
        String encryptedString = crypter.encrypt(INPUT_1);

        assertNotNull(encryptedString);
    }

    @Test
    public void shouldEncryptReturnStringWhenSpecialCharsInput() throws Exception {
        Object encryptedString = crypter.encrypt(INPUT_2);

        assertNotNull(encryptedString);
    }

    @Test
    public void shouldEncryptReturnStringWhenLongInput() throws Exception {
        Object encryptedString = crypter.encrypt(INPUT_3);

        assertNotNull(encryptedString);
    }

    @Test(expected = DecrypterException.class)
    public void shouldDecryptReturnDecrypterExceptionWhenNullText() throws Exception {
        crypter.decrypt(null);
    }

    @Test
    public void shouldDecryptReturnNotNull() throws Exception {
        String decryptedString = crypter.decrypt(WHAT_I_WANT_TO_DECRYPT);

        assertNotNull(decryptedString);
    }

    @Test
    public void shouldDecryptReturnString() throws Exception {
        Object decryptedString = crypter.decrypt(WHAT_I_WANT_TO_DECRYPT);

        assertTrue(decryptedString instanceof String);
    }

    @Test
    public void shouldCrypterReturnExpectedValueWhenEmptyInput() throws Exception {
        String whatIWantToTest = INPUT_1;
        String encryptedString = crypter.encrypt(whatIWantToTest);
        String decryptedString = crypter.decrypt(encryptedString);

        assertEquals(whatIWantToTest, decryptedString);
    }

    @Test
    public void shouldCrypterReturnExpectedValueWhenSpecialCharsInput() throws Exception {
        String whatIWantToTest = INPUT_2;
        String encryptedString = crypter.encrypt(whatIWantToTest);
        String decryptedString = crypter.decrypt(encryptedString);

        assertEquals(whatIWantToTest, decryptedString);
    }

    @Test
    public void shouldCrypterReturnExpectedValueWhenLongInput() throws Exception {
        String whatIWantToTest = INPUT_3;
        String encryptedString = crypter.encrypt(whatIWantToTest);
        String decryptedString = crypter.decrypt(encryptedString);

        assertEquals(whatIWantToTest, decryptedString);
    }

    @Test
    public void shouldDifferentCryptersReturnExpectedValueWhenEmptyInput() throws Exception {
        String whatIWantToTest = INPUT_1;

        AES256Crypter crypterInput = AES256Crypter.getInstance(KEY);
        String encryptedString = crypterInput.encrypt(whatIWantToTest);
        AES256Crypter crypterOutput = AES256Crypter.getInstance(KEY);
        String decryptedString = crypterOutput.decrypt(encryptedString);

        assertEquals(whatIWantToTest, decryptedString);
    }

    @Test
    public void shouldDifferentCryptersReturnExpectedValueWhenSpecialCharsInput() throws Exception {
        String whatIWantToTest = INPUT_2;

        AES256Crypter crypterInput = AES256Crypter.getInstance(KEY);
        String encryptedString = crypterInput.encrypt(whatIWantToTest);
        AES256Crypter crypterOutput = AES256Crypter.getInstance(KEY);
        String decryptedString = crypterOutput.decrypt(encryptedString);

        assertEquals(whatIWantToTest, decryptedString);
    }

    @Test
    public void shouldDifferentCryptersReturnExpectedValueWhenLongInput() throws Exception {
        String whatIWantToTest = INPUT_3;

        AES256Crypter crypterInput = AES256Crypter.getInstance(KEY);
        String encryptedString = crypterInput.encrypt(whatIWantToTest);
        AES256Crypter crypterOutput = AES256Crypter.getInstance(KEY);
        String decryptedString = crypterOutput.decrypt(encryptedString);

        assertEquals(whatIWantToTest, decryptedString);
    }
}