package com.example.auth_server.service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

/**
 * Utilitaire pour le calcul HMAC-SHA256 côté serveur.
 */
public class HmacUtil {

    private HmacUtil() {}

    /**
     * Calcule un HMAC-SHA256.
     * @param key clé secrète (mot de passe en clair)
     * @param data données à signer (email:nonce:timestamp)
     * @return signature hexadécimale
     */
    public static String compute(String key, String data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKey = new SecretKeySpec(
                key.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        mac.init(secretKey);
        byte[] hmacBytes = mac.doFinal(
                data.getBytes(StandardCharsets.UTF_8));
        return HexFormat.of().formatHex(hmacBytes);
    }

    /**
     * Compare deux HMAC en temps constant pour éviter les timing attacks.
     */
    public static boolean compareConstantTime(String a, String b) {
        if (a.length() != b.length()) return false;
        int result = 0;
        for (int i = 0; i < a.length(); i++) {
            result |= a.charAt(i) ^ b.charAt(i);
        }
        return result == 0;
    }
}