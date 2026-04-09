package com.example.auth_server;

import com.example.auth_server.exception.AuthenticationFailedException;
import com.example.auth_server.exception.InvalidInputException;
import com.example.auth_server.exception.ResourceConflictException;
import com.example.auth_server.service.AuthService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests unitaires pour AuthService.
 */
@SpringBootTest
@Transactional
class AuthServiceTest {

    @Autowired
    private AuthService authService;

    // Test 1 — Email vide
    @Test
    void testEmailVide() {
        assertThrows(InvalidInputException.class, () ->
                authService.register("", "pwd1234"));
    }

    // Test 2 — Format email incorrect
    @Test
    void testEmailFormatInvalide() {
        assertThrows(InvalidInputException.class, () ->
                authService.register("emailsansarobase", "pwd1234"));
    }

    // Test 3 — Mot de passe trop court
    @Test
    void testMotDePasseTropCourt() {
        assertThrows(InvalidInputException.class, () ->
                authService.register("test@example.com", "ab"));
    }

    // Test 4 — Inscription OK
    @Test
    void testInscriptionOK() {
        assertDoesNotThrow(() ->
                authService.register("nouveau@example.com", "pwd1234"));
    }

    // Test 5 — Inscription refusée si email déjà existant
    @Test
    void testInscriptionEmailDejaExistant() {
        authService.register("double@example.com", "pwd1234");
        assertThrows(ResourceConflictException.class, () ->
                authService.register("double@example.com", "pwd1234"));
    }

    // Test 6 — Login OK
    @Test
    void testLoginOK() {
        authService.register("login@example.com", "pwd1234");
        assertDoesNotThrow(() ->
                authService.login("login@example.com", "pwd1234"));
    }

    // Test 7 — Login KO si mot de passe incorrect
    @Test
    void testLoginMauvaisMotDePasse() {
        authService.register("motdepasse@example.com", "pwd1234");
        assertThrows(AuthenticationFailedException.class, () ->
                authService.login("motdepasse@example.com", "mauvais"));
    }

    // Test 8 — Login KO si email inconnu
    @Test
    void testLoginEmailInconnu() {
        assertThrows(AuthenticationFailedException.class, () ->
                authService.login("inconnu@example.com", "pwd1234"));
    }
}