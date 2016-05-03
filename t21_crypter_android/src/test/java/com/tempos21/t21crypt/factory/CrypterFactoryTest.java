package com.tempos21.t21crypt.factory;

import com.tempos21.t21crypt.crypter.AESCrypter;
import com.tempos21.t21crypt.crypter.Crypter;

import org.junit.Test;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class CrypterFactoryTest {

    private static final String KEY = "randomKey";

    private static final CryptMethod VALID_CRYPT_METHOD = CryptMethod.AES;

    private static final CryptMethod NULL_CRYPT_METHOD = null;

    private static final CryptMethod CRYPT_METHOD_AES256 = CryptMethod.AES;

    @Test
    public void shouldBuildCrypterReturnNotNullWhenValidCryptMethod() throws Exception {
        Crypter crypter = CrypterFactory.buildCrypter(VALID_CRYPT_METHOD, KEY);

        assertNotNull(crypter);
    }

    @Test
    public void shouldBuildCrypterReturnNullWhenNullCryptMethod() throws Exception {
        Crypter crypter = CrypterFactory.buildCrypter(NULL_CRYPT_METHOD, KEY);

        assertNull(crypter);
    }

    @Test
    public void shouldBuildCrypterReturnInstanceOfAES256CrypterWhenAES256CryptMethod() throws Exception {
        Crypter crypter = CrypterFactory.buildCrypter(CRYPT_METHOD_AES256, KEY);

        assertTrue(crypter instanceof AESCrypter);
    }
}