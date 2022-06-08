package com.mattwelke;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import jakarta.inject.Singleton;

@Singleton
public class EncryptionService {

    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final String SECRET_KEY_FACTORY_STRING = "PBKDF2WithHmacSHA256";

    // The Cipher instance used for encryption.
    private Cipher cipherEnc;

    // The Cipher instance used for decryption.
    private Cipher cipherDec;

    // cached Base64 encoder instance.
    private Encoder encoder;

    // cached Base64 decoder instance.
    private Decoder decoder;

    /**
     * Creates an instance of the encryption service, which can be used to encrypt
     * and decrypt data. Throws exceptions when provided with invalid configuration
     * like the algorithm to use, the password, and the salt. This represents a
     * programming error and it is desireable for the application to not finish
     * starting up when this happens.
     * 
     * @param config The encryption configuration.
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws InvalidKeySpecException
     */
    public EncryptionService(EncryptionConfiguration config) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, InvalidAlgorithmParameterException, InvalidKeySpecException {

        SecretKey key = getKeyFromPassword(config.getPassword(), config.getSalt());
        IvParameterSpec iv = generateIv();

        Cipher cipherEnc = Cipher.getInstance(ALGORITHM);
        cipherEnc.init(Cipher.ENCRYPT_MODE, key, iv);
        this.cipherEnc = cipherEnc;

        Cipher cipherDec = Cipher.getInstance(ALGORITHM);
        cipherDec.init(Cipher.DECRYPT_MODE, key, iv);
        this.cipherDec = cipherDec;

        this.encoder = Base64.getEncoder();
        this.decoder = Base64.getDecoder();
    }

    /**
     * Encrypts an input string.
     * From https://www.baeldung.com/java-aes-encryption-decryption
     * 
     * @param input The input string to be encrypted and encoded as Base64.
     * @return The encrypted input string encoded as a Base64 string.
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public String encryptString(String input) throws IllegalBlockSizeException, BadPaddingException {

        byte[] cipherText = cipherEnc.doFinal(input.getBytes());
        return encoder.encodeToString(cipherText);
    }

    /**
     * Decrypts an input string.
     * From https://www.baeldung.com/java-aes-encryption-decryption
     * 
     * @param input The input string to be decoded from Base64 and decrypted.
     * @return The input string decoded from Base64 and decrypted back to its
     *         original form before it was originally encrypted by this application.
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public String decryptString(String input) throws IllegalBlockSizeException, BadPaddingException {

        byte[] plainText = cipherDec.doFinal(decoder.decode(input));
        return new String(plainText);
    }

    // Helpers for init:

    /**
     * Creates the SecretKey.
     * From https://www.baeldung.com/java-aes-encryption-decryption
     * 
     * @param password
     * @param salt
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    private static SecretKey getKeyFromPassword(String password, String salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(SECRET_KEY_FACTORY_STRING);
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, 256);
        SecretKey secret = new SecretKeySpec(factory.generateSecret(spec)
                .getEncoded(), "AES");
        return secret;
    }

    /**
     * Creates the IvParameterSpec.
     * From https://www.baeldung.com/java-aes-encryption-decryption
     * 
     * @return
     */
    private static IvParameterSpec generateIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }
}
