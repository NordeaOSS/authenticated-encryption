package com.nordea.oss.authenticatedencryption;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.Base64;

/**
 * Authenticated Encryption (AE), Authenticated Encryption with Associated Data (AEAD)
 *
 * Copyright (c) 2017. Niels Bo <niels.bo@nordea.com>
 * Copyright (c) 2017. Nordea Bank AB
 * Licensed under the MIT license (LICENSE.txt)
 */


class AuthenticatedEncryption {
    private static final String cipher_type = "AES/CBC/PKCS5Padding";//same as PKCS7 padding mode
    private static int IV_SIZE = 16;//128 bit
    private final byte[] encryption_key;
    private final byte[] auth_key;

    public AuthenticatedEncryption(byte[] encryption_key, byte[] auth_key) {
        this.encryption_key = encryption_key;
        this.auth_key = auth_key;
    }

    public AuthenticatedEncryption(String encryption_key, String auth_key) throws Exception {
        this(Base64.getDecoder().decode(encryption_key), Base64.getDecoder().decode((auth_key)));
    }

    public String encrypt(String input) throws Exception {
        return encrypt(input.getBytes("UTF-8"));
    }

    public String encrypt(byte[] input) throws Exception {
        byte[] iv = generateIV();
        byte[] ciphertext = encrypt(encryption_key, iv, input);
        byte[] ivcipher = concat(iv, ciphertext);
        byte[] hmac = generateHMAC(auth_key, ivcipher);
        return Base64.getEncoder().encodeToString(concat(ivcipher, hmac));
    }

    public String decrypt(String base64_payload) throws Exception {
        return this.decrypt(Base64.getDecoder().decode(base64_payload));
    }

    public String decrypt(byte[] encrypted_payload) throws Exception {
        byte[] iv = Arrays.copyOf(encrypted_payload, IV_SIZE);
        int macLenght = hmacLength(auth_key);
        byte[] hmac1 = Arrays.copyOfRange(encrypted_payload, IV_SIZE + macLenght, encrypted_payload.length);
        byte[] ciphertext = Arrays.copyOfRange(encrypted_payload, IV_SIZE, encrypted_payload.length - macLenght);
        byte[] data = concat(iv, ciphertext);
        byte[] hmac2 = generateHMAC(auth_key, data);
        if (Arrays.equals(hmac1, hmac2)) {
            byte[] decrypt = decrypt(encryption_key, iv, ciphertext);
            return new String(decrypt, "UTF-8");
        } else {
            throw new RuntimeException("Incorrect HMAC");
        }
    }

    private byte[] generateIV() throws Exception {
        byte[] iv = new byte[IV_SIZE];
        SecureRandom randomSecureRandom = SecureRandom.getInstance("SHA1PRNG");
        randomSecureRandom.nextBytes(iv);
        return iv;
    }

    private byte[] encrypt(byte[] skey, byte[] iv, byte[] data) throws Exception {
        SecretKeySpec key = new SecretKeySpec(skey, "AES");
        Cipher cipher = Cipher.getInstance(cipher_type);
        AlgorithmParameterSpec param = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, param);
        return cipher.doFinal(data);
    }

    private byte[] decrypt(byte[] skey, byte[] iv, byte[] data) throws Exception {
        SecretKeySpec key = new SecretKeySpec(skey, "AES");
        AlgorithmParameterSpec param = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance(cipher_type);
        cipher.init(Cipher.DECRYPT_MODE, key, param);
        return cipher.doFinal(data);
    }

    /*
     * Generate Hashed Message Authentication Code (HMAC)
     */
    private byte[] generateHMAC(byte[] skey, byte[] data) throws Exception {
        SecretKeySpec key = new SecretKeySpec(skey, "HmacSHA256");
        Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
        sha256_HMAC.init(key);
        return sha256_HMAC.doFinal(data);
    }

    private int hmacLength(byte[] skey) throws Exception {
        SecretKeySpec key = new SecretKeySpec(skey, "HmacSHA256");
        Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
        sha256_HMAC.init(key);
        return sha256_HMAC.getMacLength();
    }

    private byte[] concat(byte[] first, byte[] second) {
        byte[] result = Arrays.copyOf(first, first.length + second.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }
}