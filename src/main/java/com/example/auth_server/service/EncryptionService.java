package com.example.auth_server.service;

import com.example.auth_server.exception.InvalidInputException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Service de chiffrement AES-GCM avec Master Key.
 */
@Service
public class EncryptionService {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;
    private static final String VERSION = "v1";
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final SecretKey masterKey;

    /**
     * Initialise le service avec la Master Key injectée via variable d'environnement.
     */
    public EncryptionService(@Value("${APP_MASTER_KEY}") String masterKeyStr) {
        if (masterKeyStr == null || masterKeyStr.isBlank()) {
            throw new InvalidInputException(
                    "APP_MASTER_KEY est absente — l'application ne peut pas démarrer");
        }
        byte[] keyBytes = masterKeyStr.getBytes(StandardCharsets.UTF_8);
        byte[] key32 = new byte[32];
        System.arraycopy(keyBytes, 0, key32, 0, Math.min(keyBytes.length, 32));
        this.masterKey = new SecretKeySpec(key32, "AES");
    }

    /**
     * Chiffre un texte en clair avec AES-GCM.
     */
    public String encrypt(String plaintext)
            throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, InvalidAlgorithmParameterException,
            IllegalBlockSizeException, BadPaddingException {

        byte[] iv = new byte[GCM_IV_LENGTH];
        SECURE_RANDOM.nextBytes(iv);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, masterKey, parameterSpec);

        byte[] ciphertext = cipher.doFinal(
                plaintext.getBytes(StandardCharsets.UTF_8));

        String ivBase64 = Base64.getEncoder().encodeToString(iv);
        String ciphertextBase64 = Base64.getEncoder().encodeToString(ciphertext);

        return VERSION + ":" + ivBase64 + ":" + ciphertextBase64;
    }

    /**
     * Déchiffre un texte chiffré avec AES-GCM.
     */
    public String decrypt(String encryptedData)
            throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, InvalidAlgorithmParameterException,
            IllegalBlockSizeException, BadPaddingException {

        String[] parts = encryptedData.split(":");
        if (parts.length != 3 || !VERSION.equals(parts[0])) {
            throw new InvalidInputException("Format de données chiffrées invalide");
        }

        byte[] iv = Base64.getDecoder().decode(parts[1]);
        byte[] ciphertext = Base64.getDecoder().decode(parts[2]);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, masterKey, parameterSpec);

        byte[] plaintext = cipher.doFinal(ciphertext);
        return new String(plaintext, StandardCharsets.UTF_8);
    }
}