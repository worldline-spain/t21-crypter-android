package com.tempos21.t21crypt.crypter;

/**
 * Public interface that defines an encryption and decryption method class implementation.
 */
public interface OldCrypter {

    /**
     * Encrypts a String with the passed key
     *
     * @param key       String needed to encrypt
     * @param plainText String to be encrypted
     * @return String encrypted based on the key and plainText
     */
    public String encrypt(String key, String plainText);

    /**
     * Decrypts a String with the passed key
     *
     * @param key         String needed to decrypt
     * @param cryptedText String to be decrypted
     * @return String decrypted based on the key and cryptedText
     */
    public String decrypt(String key, String cryptedText);
}
