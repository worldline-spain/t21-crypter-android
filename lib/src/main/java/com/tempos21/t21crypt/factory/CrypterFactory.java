package com.tempos21.t21crypt.factory;


import com.tempos21.t21crypt.crypter.AES256Crypter;
import com.tempos21.t21crypt.crypter.Crypter;
import com.tempos21.t21crypt.exception.CrypterException;

/**
 * Factory that constructs a Crypter based on a @CryptMethod.
 */
public class CrypterFactory {

    /**
     * Builds a @Crypter based on the @CryptMethod specified.
     *
     * @param method @CryptMethod to construct the @Crypter
     *
     * @return an implementation of @Crypter
     */
    public static Crypter buildCrypter(CryptMethod method, String key) throws CrypterException {
        Crypter crypter = null;

        if (method != null) {
            switch (method) {
                case AES256:
                    crypter = AES256Crypter.getInstance(key);
                    break;

                default:
                    break;
            }
        }

        return crypter;
    }
}
