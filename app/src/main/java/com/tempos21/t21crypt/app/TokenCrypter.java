package com.tempos21.t21crypt.app;

import com.tempos21.t21crypt.crypter.Crypter;
import com.tempos21.t21crypt.exception.CrypterException;
import com.tempos21.t21crypt.exception.DecrypterException;
import com.tempos21.t21crypt.exception.EncrypterException;
import com.tempos21.t21crypt.factory.CryptMethod;
import com.tempos21.t21crypt.factory.CrypterFactory;

public final class TokenCrypter {

    /**
     * This key should be dynamic
     */
    private static final String KEY_TOKEN = "RANDOM_STRING";

    private Crypter crypter = null;

    public TokenCrypter() {
        try {
            crypter = CrypterFactory.buildCrypter(CryptMethod.AES256, KEY_TOKEN);
        } catch (CrypterException e) {
            e.printStackTrace();
        }
    }

    public String encryptToken(String token) {
        String encrypt = null;

        try {
            encrypt = crypter.encrypt(token);
        } catch (EncrypterException e) {
            e.printStackTrace();
        }
        return encrypt;
    }

    public String decryptToken(String token) {
        String decrypt = null;

        try {
            decrypt = crypter.decrypt(token);
        } catch (DecrypterException e) {
            e.printStackTrace();
        }
        return decrypt;
    }
}
