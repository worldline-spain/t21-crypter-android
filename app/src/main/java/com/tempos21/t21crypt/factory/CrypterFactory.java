package com.tempos21.t21crypt.factory;


import com.tempos21.t21crypt.crypter.AES256Crypter;
import com.tempos21.t21crypt.crypter.Crypter;

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
    public static Crypter buildCrypter(CryptMethod method) {
        Crypter crypter = null;

        switch (method) {
            case AES256:
                crypter = new AES256Crypter();
                break;

            default:
                break;
        }

        return crypter;
    }
}
