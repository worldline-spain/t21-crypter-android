package com.tempos21.t21crypt.crypter;

import com.tempos21.t21crypt.cipher.AES256Cipher;

import android.util.Base64;
import android.util.Log;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * AES256 Crypter. Encrypts and decrypts a string based on a key.</br></br>
 * <p/>
 * This class needs a key in order to encrypt and decrypt the String, this key can be any length
 * and
 * </br>
 * the complexity of it is up to the user. We recommend a key of 15 chars length with lower and
 * </br>
 * upper case, numbers and special characters.
 */
public class AES256Crypter implements Crypter {

    private static final String TAG = AES256Crypter.class.getSimpleName();

    private static final String ENCODING = "UTF-8";

    private static final String PASS_HASH_ALGORITHM = "SHA-256";

    /**
     * Encrypts a String with the passed key
     *
     * @param key       String needed to encrypt
     * @param plainText String to be encrypted
     *
     * @return String encrypted based on the key and plainText
     */
    @Override
    public String encrypt(String key, String plainText) {
        byte[] encryptedBytes = new byte[0];

        try {
            encryptedBytes = AES256Cipher.encrypt(buildKey(key), plainText.getBytes(ENCODING));
        } catch (UnsupportedEncodingException e) {
            Log.e(TAG, "ERROR while encrypting text", e);
        } catch (NoSuchPaddingException e) {
            Log.e(TAG, "ERROR while encrypting text", e);
        } catch (InvalidAlgorithmParameterException e) {
            Log.e(TAG, "ERROR while encrypting text", e);
        } catch (NoSuchAlgorithmException e) {
            Log.e(TAG, "ERROR while encrypting text", e);
        } catch (IllegalBlockSizeException e) {
            Log.e(TAG, "ERROR while encrypting text", e);
        } catch (BadPaddingException e) {
            Log.e(TAG, "ERROR while encrypting text", e);
        } catch (InvalidKeyException e) {
            Log.e(TAG, "ERROR while encrypting text", e);
        }

        return Base64.encodeToString(encryptedBytes, Base64.DEFAULT);
    }

    /**
     * Decrypts a String with the passed key
     *
     * @param key         String needed to decrypt
     * @param cryptedText String to be decrypted
     *
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
        } catch (UnsupportedEncodingException e) {
            Log.e(TAG, "ERROR while decrypting text", e);
        } catch (NoSuchPaddingException e) {
            Log.e(TAG, "ERROR while decrypting text", e);
        } catch (InvalidAlgorithmParameterException e) {
            Log.e(TAG, "ERROR while decrypting text", e);
        } catch (NoSuchAlgorithmException e) {
            Log.e(TAG, "ERROR while decrypting text", e);
        } catch (IllegalBlockSizeException e) {
            Log.e(TAG, "ERROR while decrypting text", e);
        } catch (BadPaddingException e) {
            Log.e(TAG, "ERROR while decrypting text", e);
        } catch (InvalidKeyException e) {
            Log.e(TAG, "ERROR while decrypting text", e);
        }

        return decryptedToken;
    }

    /**
     * Constructs a valid key based on the String key passed by user
     *
     * @param key String needed to construct the binary key
     *
     * @return a binary key of 32 bits
     */
    private byte[] buildKey(String key)
            throws NoSuchAlgorithmException, UnsupportedEncodingException {
        MessageDigest digester = MessageDigest.getInstance(PASS_HASH_ALGORITHM);
        digester.update(key.getBytes(ENCODING));
        byte[] codedKey = digester.digest();

        return codedKey;
    }
}
