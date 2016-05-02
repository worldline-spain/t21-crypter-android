package com.tempos21.t21crypt.crypter;

import com.tempos21.t21crypt.exception.CrypterException;
import com.tempos21.t21crypt.exception.DecrypterException;
import com.tempos21.t21crypt.exception.EncrypterException;

import org.apache.commons.codec.binary.Base64;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

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

    private static final String AES_KEY_ALGORITHM = "AES";

    private static final String AES_TRANSFORMATION = "AES/CBC/PKCS5Padding";

    private static final String ENCODING = "UTF-8";

    private static final String PASS_HASH_ALGORITHM = "SHA-256";

    private static final String KEY_CANNOT_BE_NULL = "Key cannot be null";

    private static final String TEXT_CANNOT_BE_NULL = "Text cannot be null";

    private static final String KEY_INVALID_SIZE = "Invalid key? Have you tried to install JCE? Take a look to Javadoc :)";

    private static AES256Crypter INSTANCE;

    private Cipher cipher;

    private SecretKeySpec secretKeySpec;

    private AlgorithmParameterSpec ivSpec;

    /**
     * Creates an instance of AES256 crypter.
     * <p/>
     * NOTE: By default, Java restricts key size to 128 bits. Nowadays this restriction is questionable, in order to remove this
     * restriction you should install these packages:
     * <p/>
     * http://www.oracle.com/technetwork/java/javase/downloads/jce-6-download-429243.html
     * http://www.oracle.com/technetwork/java/javase/downloads/jce-7-download-432124.html
     * http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html
     *
     * @param key String password to use for the en/decrypt the desired text.
     *
     * @return and instance of {@link AES256Crypter}
     *
     * @throws CrypterException exception if NoSuchAlgorithmException | NoSuchPaddingException | UnsupportedEncodingException
     *                          occurs
     */
    public static AES256Crypter getInstance(String key) throws CrypterException {
        if (key == null) {
            throw new CrypterException(KEY_CANNOT_BE_NULL);
        }

        if (INSTANCE == null) {
            INSTANCE = new AES256Crypter(key);
        }
        return INSTANCE;
    }

    private AES256Crypter(String key) throws CrypterException {
        try {
            cipher = getCipher();
            secretKeySpec = getKey(buildKey(key));
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | UnsupportedEncodingException e) {
            throw new CrypterException(e.getMessage());
        }
        ivSpec = getIvParameterSpec();
    }

    /**
     * Encrypts a String.
     *
     * @param plainText String to be encrypted
     *
     * @return String encrypted based on the key and plainText
     */
    @Override
    public String encrypt(String plainText) throws EncrypterException {
        byte[] encryptedBytes;
        String encryptedString;

        if (plainText == null) {
            throw new EncrypterException(TEXT_CANNOT_BE_NULL);
        }

        try {
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec);
            encryptedBytes = cipher.doFinal(plainText.getBytes(ENCODING));
            encryptedString = new String(Base64.encodeBase64(encryptedBytes), ENCODING);
        } catch (InvalidKeyException e) {
            throw new EncrypterException(KEY_INVALID_SIZE);
        } catch (UnsupportedEncodingException | BadPaddingException | IllegalBlockSizeException |
                InvalidAlgorithmParameterException e) {
            throw new EncrypterException(e.getMessage());
        }

        return encryptedString;
    }

    /**
     * Decrypts a String with the passed key
     *
     * @param cryptedText String to be decrypted
     *
     * @return String decrypted based on the key and cryptedText
     */
    @Override
    public String decrypt(String cryptedText) throws DecrypterException {
        String decryptedToken;
        byte[] decryptedBytes;

        if (cryptedText == null) {
            throw new DecrypterException(TEXT_CANNOT_BE_NULL);
        }

        try {
            byte[] cryptedTextBytes = Base64.decodeBase64(cryptedText.getBytes(ENCODING));
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivSpec);
            decryptedBytes = cipher.doFinal(cryptedTextBytes);
            decryptedToken = new String(decryptedBytes, ENCODING);
        } catch (InvalidKeyException e) {
            throw new DecrypterException(KEY_INVALID_SIZE + " - Error message: " + e.getMessage());
        } catch (UnsupportedEncodingException | BadPaddingException | IllegalBlockSizeException |
                InvalidAlgorithmParameterException e) {
            throw new DecrypterException(e.getMessage());
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
    private byte[] buildKey(String key) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        MessageDigest digester = MessageDigest.getInstance(PASS_HASH_ALGORITHM);
        digester.update(key.getBytes(ENCODING));
        byte[] keyBytes = new byte[16];
        System.arraycopy(digester.digest(), 0, keyBytes, 0, keyBytes.length);
        return keyBytes;
    }

    private IvParameterSpec getIvParameterSpec() {
        byte[] iv = new byte[cipher.getBlockSize()];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    private Cipher getCipher() throws NoSuchAlgorithmException, NoSuchPaddingException {
        return Cipher.getInstance(AES_TRANSFORMATION);
    }

    private SecretKeySpec getKey(byte[] keyBytes) {
        return new SecretKeySpec(keyBytes, AES_KEY_ALGORITHM);
    }
}
