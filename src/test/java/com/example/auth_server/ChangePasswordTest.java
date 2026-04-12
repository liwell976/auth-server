package com.example.auth_server;

import com.example.auth_server.exception.AuthenticationFailedException;
import com.example.auth_server.exception.InvalidInputException;
import com.example.auth_server.service.AuthService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@Transactional
@ActiveProfiles("test")
class ChangePasswordTest {

    @Autowired
    private AuthService authService;

    // Test 1 — Changement de mot de passe réussi
    @Test
    void testChangementMotDePasseReussi() {
        authService.register("change@example.com", "Password123!");
        assertDoesNotThrow(() ->
                authService.changePassword(
                        "change@example.com",
                        "Password123!",
                        "NewPassword456@",
                        "NewPassword456@"));
    }

    // Test 2 — Ancien mot de passe incorrect
    @Test
    void testAncienMotDePasseIncorrect() {
        authService.register("old@example.com", "Password123!");
        assertThrows(AuthenticationFailedException.class, () ->
                authService.changePassword(
                        "old@example.com",
                        "Mauvais123!",
                        "NewPassword456@",
                        "NewPassword456@"));
    }

    // Test 3 — Confirmation différente
    @Test
    void testConfirmationDifferente() {
        authService.register("confirm@example.com", "Password123!");
        assertThrows(InvalidInputException.class, () ->
                authService.changePassword(
                        "confirm@example.com",
                        "Password123!",
                        "NewPassword456@",
                        "Different456@"));
    }

    // Test 4 — Nouveau mot de passe trop faible
    @Test
    void testNouveauMotDePasseTropFaible() {
        authService.register("weak@example.com", "Password123!");
        assertThrows(InvalidInputException.class, () ->
                authService.changePassword(
                        "weak@example.com",
                        "Password123!",
                        "faible",
                        "faible"));
    }

    // Test 5 — Utilisateur inexistant
    @Test
    void testUtilisateurInexistant() {
        assertThrows(AuthenticationFailedException.class, () ->
                authService.changePassword(
                        "inexistant@example.com",
                        "Password123!",
                        "NewPassword456@",
                        "NewPassword456@"));
    }
}