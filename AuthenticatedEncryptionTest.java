package com.nordea.oss.authenticatedencryption;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.util.Base64;

/**
 * Copyright (c) 2017. Niels Bo <niels.bo@nordea.com>
 * Copyright (c) 2017. Nordea Bank AB
 * Licensed under the MIT license (LICENSE.txt)
 */
public class AuthenticatedEncryptionTest {

    public static void main(String[] args) throws Exception {

        String encryption = makeKey();
        String auth = makeKey();
        String payload = "{\"email\":\"niels.bo@nordea.com\"}";

        System.out.println("Encryption key: " + encryption);
        System.out.println("Authorisation key: " + auth);
        System.out.println("Payload: " + payload);

        AuthenticatedEncryption authenticatedEncryption = new AuthenticatedEncryption(encryption, auth);
        String encrypted = authenticatedEncryption.encrypt(payload);
        System.out.println("Authenticated and encrypted payload: " + encrypted);

        String decrypted = authenticatedEncryption.decrypt(encrypted);
        System.out.println("Verified and decrypted: " + decrypted);
    }

    private static String makeKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey secretKey = keyGen.generateKey();
        byte[] secretKeyEncoded = secretKey.getEncoded();
        return Base64.getEncoder().encodeToString(secretKeyEncoded);
    }
}
