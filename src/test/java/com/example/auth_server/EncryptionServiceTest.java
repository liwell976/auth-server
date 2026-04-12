package com.example.auth_server;

import com.example.auth_server.service.EncryptionService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@ActiveProfiles("test")
class EncryptionServiceTest {

    @Autowired
    private EncryptionService encryptionService;

    // Test 1 — Chiffrement/déchiffrement OK
    @Test
    void testEncryptDecryptOK() throws Exception {
        String plaintext = "Password123!";
        String encrypted = encryptionService.encrypt(plaintext);
        String decrypted = encryptionService.decrypt(encrypted);
        assertEquals(plaintext, decrypted);
    }

    // Test 2 — Le texte chiffré est différent du texte clair
    @Test
    void testEncryptedDifferentFromPlain() throws Exception {
        String plaintext = "Password123!";
        String encrypted = encryptionService.encrypt(plaintext);
        assertNotEquals(plaintext, encrypted);
    }

    // Test 3 — Deux chiffrements du même texte donnent des résultats différents (IV aléatoire)
    @Test
    void testEncryptTwiceGivesDifferentResults() throws Exception {
        String plaintext = "Password123!";
        String encrypted1 = encryptionService.encrypt(plaintext);
        String encrypted2 = encryptionService.encrypt(plaintext);
        assertNotEquals(encrypted1, encrypted2);
    }

    // Test 4 — Déchiffrement KO si ciphertext modifié
    @Test
    void testDecryptFailsIfModified() throws Exception {
        String encrypted = encryptionService.encrypt("Password123!");
        String modified = encrypted + "tampered";
        assertThrows(Exception.class, () ->
                encryptionService.decrypt(modified));
    }

    // Test 5 — Format de stockage correct
    @Test
    void testEncryptedFormat() throws Exception {
        String encrypted = encryptionService.encrypt("Password123!");
        String[] parts = encrypted.split(":");
        assertEquals(3, parts.length);
        assertEquals("v1", parts[0]);
    }
}