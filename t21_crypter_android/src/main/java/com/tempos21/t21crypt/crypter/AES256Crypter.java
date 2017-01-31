package com.tempos21.t21crypt.crypter;

import android.util.Base64;
import android.util.Log;

import com.tempos21.t21crypt.cipher.AES256Cipher;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * AES256 Crypter. Encrypts and decrypts a string based on a key.
 * This class needs a key in order to encrypt and decrypt the String,
 * this key can be any length and the complexity of it is up to the user.
 * We recommend a key of 15 chars length with lower and upper case, numbers and special characters.
 */
public class AES256Crypter implements OldCrypter {

    private static final String ENCODING = "UTF-8";

    private static final String PASS_HASH_ALGORITHM = "SHA-256";

    /**
     * Encrypts a String with the passed key
     *
     * @param key       String needed to encrypt
     * @param plainText String to be encrypted
     * @return String encrypted based on the key and plainText
     */
    @Override
    public String encrypt(String key, String plainText) {
        byte[] encryptedBytes = new byte[0];

        try {
            encryptedBytes = AES256Cipher.encrypt(buildKey(key), plainText.getBytes(ENCODING));
        } catch (Exception e) {
            Log.e("ERROR while encrypting", e.toString());
        }

        return Base64.encodeToString(encryptedBytes, Base64.DEFAULT);
    }

    /**
     * Decrypts a String with the passed key
     *
     * @param key         String needed to decrypt
     * @param cryptedText String to be decrypted
     * @return String decrypted based on the key and cryptedText
     */
    @Override
    public String decrypt(String key, String cryptedText) {
        String decryptedToken = null;
        byte[] decryptedBytes;
        try {
            decryptedBytes = AES256Cipher.decrypt(buildKey(key),
                    Base64.decode(cryptedText.getBytes(ENCODING), Base64.DEFAULT));
            decryptedToken = new String(decryptedBytes, ENCODING);
        } catch (Exception e) {
            Log.e("ERROR while encrypting", e.toString());
        }

        return decryptedToken;
    }

    /**
     * Constructs a valid key based on the String key passed by user
     *
     * @param key String needed to construct the binary key
     * @return a binary key of 32 bits
     */
    private byte[] buildKey(String key)
            throws NoSuchAlgorithmException, UnsupportedEncodingException {
        MessageDigest digester = MessageDigest.getInstance(PASS_HASH_ALGORITHM);
        digester.update(key.getBytes(ENCODING));
        return digester.digest();
    }
}
