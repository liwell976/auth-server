package com.example.auth_server;

import com.example.auth_server.exception.AuthenticationFailedException;
import com.example.auth_server.exception.InvalidInputException;
import com.example.auth_server.exception.ResourceConflictException;
import com.example.auth_server.service.AuthService;
import com.example.auth_server.service.CryptoService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@Transactional
class AuthServiceTest {

    @Autowired
    private AuthService authService;

    @Autowired
    private CryptoService cryptoService;

    // Test 1 — Email vide
    @Test
    void testEmailVide() {
        assertThrows(InvalidInputException.class, () ->
                authService.register("", "Password123!"));
    }

    // Test 2 — Format email incorrect
    @Test
    void testEmailFormatInvalide() {
        assertThrows(InvalidInputException.class, () ->
                authService.register("emailsansarobase", "Password123!"));
    }

    // Test 3 — Mot de passe trop court
    @Test
    void testMotDePasseTropCourt() {
        assertThrows(InvalidInputException.class, () ->
                authService.register("test@example.com", "ab"));
    }

    // Test 4 — Mot de passe sans majuscule
    @Test
    void testMotDePasseSansMajuscule() {
        assertThrows(InvalidInputException.class, () ->
                authService.register("test@example.com", "password123!"));
    }

    // Test 5 — Mot de passe sans minuscule
    @Test
    void testMotDePasseSansMinuscule() {
        assertThrows(InvalidInputException.class, () ->
                authService.register("test@example.com", "PASSWORD123!"));
    }

    // Test 6 — Mot de passe sans chiffre
    @Test
    void testMotDePasseSansChiffre() {
        assertThrows(InvalidInputException.class, () ->
                authService.register("test@example.com", "Password!!!abc"));
    }

    // Test 7 — Mot de passe sans caractère spécial
    @Test
    void testMotDePasseSansSpecial() {
        assertThrows(InvalidInputException.class, () ->
                authService.register("test@example.com", "Password12345"));
    }

    // Test 8 — Inscription OK
    @Test
    void testInscriptionOK() {
        assertDoesNotThrow(() ->
                authService.register("nouveau@example.com", "Password123!"));
    }

    // Test 9 — Inscription refusée si email déjà existant
    @Test
    void testInscriptionEmailDejaExistant() {
        authService.register("double@example.com", "Password123!");
        assertThrows(ResourceConflictException.class, () ->
                authService.register("double@example.com", "Password123!"));
    }

    // Test 10 — Login OK avec HMAC valide
    @Test
    void testLoginHmacOK() throws Exception {
        authService.register("login@example.com", "Password123!");
        String nonce = UUID.randomUUID().toString();
        long timestamp = Instant.now().getEpochSecond();
        String message = "login@example.com:" + nonce + ":" + timestamp;
        String hmac = com.example.auth_server.service.HmacUtil.compute(
                "Password123!", message);
        assertDoesNotThrow(() ->
                cryptoService.verifyHmacAndLogin(
                        "login@example.com", nonce, timestamp, hmac));
    }

    // Test 11 — Login KO si HMAC invalide
    @Test
    void testLoginHmacInvalide() {
        authService.register("hmac@example.com", "Password123!");
        String nonce = UUID.randomUUID().toString();
        long timestamp = Instant.now().getEpochSecond();
        assertThrows(AuthenticationFailedException.class, () ->
                cryptoService.verifyHmacAndLogin(
                        "hmac@example.com", nonce, timestamp, "hmac_invalide"));
    }

    // Test 12 — Login KO si timestamp expiré
    @Test
    void testLoginTimestampExpire() {
        authService.register("timestamp@example.com", "Password123!");
        String nonce = UUID.randomUUID().toString();
        long oldTimestamp = Instant.now().getEpochSecond() - 120;
        assertThrows(AuthenticationFailedException.class, () ->
                cryptoService.verifyHmacAndLogin(
                        "timestamp@example.com", nonce, oldTimestamp, "hmac"));
    }

    // Test 13 — Login KO si timestamp futur
    @Test
    void testLoginTimestampFutur() {
        authService.register("futur@example.com", "Password123!");
        String nonce = UUID.randomUUID().toString();
        long futureTimestamp = Instant.now().getEpochSecond() + 120;
        assertThrows(AuthenticationFailedException.class, () ->
                cryptoService.verifyHmacAndLogin(
                        "futur@example.com", nonce, futureTimestamp, "hmac"));
    }

    // Test 14 — Login KO si nonce déjà utilisé
    @Test
    void testLoginNonceDejaUtilise() throws Exception {
        authService.register("nonce@example.com", "Password123!");
        String nonce = UUID.randomUUID().toString();
        long timestamp = Instant.now().getEpochSecond();
        String message = "nonce@example.com:" + nonce + ":" + timestamp;
        String hmac = com.example.auth_server.service.HmacUtil.compute(
                "Password123!", message);
        cryptoService.verifyHmacAndLogin(
                "nonce@example.com", nonce, timestamp, hmac);
        assertThrows(AuthenticationFailedException.class, () ->
                cryptoService.verifyHmacAndLogin(
                        "nonce@example.com", nonce, timestamp, hmac));
    }

    // Test 15 — Login KO si email inconnu
    @Test
    void testLoginEmailInconnu() {
        assertThrows(AuthenticationFailedException.class, () ->
                cryptoService.verifyHmacAndLogin(
                        "inconnu@example.com", "nonce",
                        Instant.now().getEpochSecond(), "hmac"));
    }

    // Test 16 — Même message erreur pour email inconnu et HMAC invalide
    @Test
    void testMemeMessageErreur() {
        authService.register("same@example.com", "Password123!");

        AuthenticationFailedException ex1 = assertThrows(
                AuthenticationFailedException.class, () ->
                        cryptoService.verifyHmacAndLogin(
                                "inconnu@example.com", "nonce",
                                Instant.now().getEpochSecond(), "hmac"));

        AuthenticationFailedException ex2 = assertThrows(
                AuthenticationFailedException.class, () ->
                        cryptoService.verifyHmacAndLogin(
                                "same@example.com", "nonce",
                                Instant.now().getEpochSecond(), "hmac_invalide"));

        assertEquals(ex1.getMessage(), ex2.getMessage());
    }
}