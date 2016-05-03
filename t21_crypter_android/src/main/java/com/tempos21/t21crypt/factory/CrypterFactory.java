package com.tempos21.t21crypt.factory;


import com.tempos21.t21crypt.crypter.AESCrypter;
import com.tempos21.t21crypt.crypter.Crypter;
import com.tempos21.t21crypt.exception.CrypterException;

/**
 * Factory that constructs a {@link Crypter} based on a {@link CryptMethod}.
 */
public class CrypterFactory {

    /**
     * Builds a {@link Crypter} based on the {@link CryptMethod} specified.
     *
     * @param method {@link CryptMethod} to construct the {@link Crypter}
     * @param key String key that will be used to encrypt and decrypt.
     *
     * @return an implementation of {@link Crypter}
     */
    public static Crypter buildCrypter(CryptMethod method, String key) throws CrypterException {
        Crypter crypter = null;

        if (method != null) {
            switch (method) {
                case AES:
                    crypter = AESCrypter.getInstance(key);
                    break;

                default:
                    break;
            }
        }

        return crypter;
    }
}
