package com.tempos21.t21crypt.crypter;

import com.tempos21.t21crypt.exception.DecrypterException;
import com.tempos21.t21crypt.exception.EncrypterException;

/**
 * Public interface that defines an encryption and decryption method class implementation.
 */
public interface Crypter {

    /**
     * Encrypts a String with the passed key
     *
     * @param plainText String to be encrypted
     *
     * @return String encrypted based on the key and plainText
     */
    String encrypt(String plainText) throws EncrypterException;

    /**
     * Decrypts a String with the passed key
     *
     * @param cryptedText String to be decrypted
     *
     * @return String decrypted based on the key and cryptedText
     */
    String decrypt(String cryptedText) throws DecrypterException;
}
