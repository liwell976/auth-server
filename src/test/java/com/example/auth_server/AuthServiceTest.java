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

@SpringBootTest
@Transactional
class AuthServiceTest {

    @Autowired
    private AuthService authService;

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

    // Test 5 — Inscription OK
    @Test
    void testInscriptionOK() {
        assertDoesNotThrow(() ->
                authService.register("nouveau@example.com", "Password123!"));
    }

    // Test 6 — Inscription refusée si email déjà existant
    @Test
    void testInscriptionEmailDejaExistant() {
        authService.register("double@example.com", "Password123!");
        assertThrows(ResourceConflictException.class, () ->
                authService.register("double@example.com", "Password123!"));
    }

    // Test 7 — Login OK
    @Test
    void testLoginOK() {
        authService.register("login@example.com", "Password123!");
        assertDoesNotThrow(() ->
                authService.login("login@example.com", "Password123!"));
    }

    // Test 8 — Login KO si mot de passe incorrect
    @Test
    void testLoginMauvaisMotDePasse() {
        authService.register("motdepasse@example.com", "Password123!");
        assertThrows(AuthenticationFailedException.class, () ->
                authService.login("motdepasse@example.com", "Mauvais123!"));
    }

    // Test 9 — Login KO si email inconnu
    @Test
    void testLoginEmailInconnu() {
        assertThrows(AuthenticationFailedException.class, () ->
                authService.login("inconnu@example.com", "Password123!"));
    }

    // Test 10 — Même message d'erreur pour email inconnu et mauvais mot de passe
    @Test
    void testMemeMessageErreurLoginKO() {
        authService.register("same@example.com", "Password123!");

        AuthenticationFailedException ex1 = assertThrows(
                AuthenticationFailedException.class, () ->
                        authService.login("inconnu@example.com", "Password123!"));

        AuthenticationFailedException ex2 = assertThrows(
                AuthenticationFailedException.class, () ->
                        authService.login("same@example.com", "Mauvais123!"));

        assertEquals(ex1.getMessage(), ex2.getMessage());
    }

    // Test 11 — Mot de passe sans minuscule
    @Test
    void testMotDePasseSansMinuscule() {
        assertThrows(InvalidInputException.class, () ->
                authService.register("test@example.com", "PASSWORD123!"));
    }

    // Test 12 — Mot de passe sans chiffre
    @Test
    void testMotDePasseSansChiffre() {
        assertThrows(InvalidInputException.class, () ->
                authService.register("test@example.com", "Password!!!abc"));
    }

    // Test 13 — Mot de passe sans caractère spécial
    @Test
    void testMotDePasseSansSpecial() {
        assertThrows(InvalidInputException.class, () ->
                authService.register("test@example.com", "Password12345"));
    }

    // Test 14 — Lockout après 5 tentatives
    @Test
    void testLockoutApres5Tentatives() {
        authService.register("lockout@example.com", "Password123!");
        for (int i = 0; i < 5; i++) {
            try {
                authService.login("lockout@example.com", "Mauvais123!");
            } catch (AuthenticationFailedException e) {
                // attendu
            }
        }
        assertThrows(AuthenticationFailedException.class, () ->
                authService.login("lockout@example.com", "Password123!"));
    }
}