package com.example.auth_server.controller;

import com.example.auth_server.entity.User;
import com.example.auth_server.exception.AuthenticationFailedException;
import com.example.auth_server.service.AuthService;
import com.example.auth_server.service.CryptoService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Controller REST pour les endpoints d'authentification.
 *
 * ATTENTION : Cette implémentation est volontairement dangereuse
 * et ne doit jamais être utilisée en production.
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;
    private final CryptoService cryptoService;

    public AuthController(AuthService authService, CryptoService cryptoService) {
        this.authService = authService;
        this.cryptoService = cryptoService;
    }

    /**
     * Endpoint d'inscription.
     * POST /api/auth/register
     */
    @PostMapping("/register")
    public ResponseEntity<Map<String, Object>> register(
            @RequestParam String email,
            @RequestParam String password) {
        User user = authService.register(email, password);
        return ResponseEntity.status(HttpStatus.CREATED).body(Map.of(
                "message", "Inscription réussie",
                "email", user.getEmail()
        ));
    }

    /**
     * Endpoint de login HMAC.
     * POST /api/auth/login
     */
    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(
            @RequestBody LoginRequest loginRequest) {
        String token = cryptoService.verifyHmacAndLogin(
                loginRequest.getEmail(),
                loginRequest.getNonce(),
                loginRequest.getTimestamp(),
                loginRequest.getHmac()
        );
        return ResponseEntity.ok(Map.of(
                "accessToken", token,
                "expiresAt", System.currentTimeMillis() + (15 * 60 * 1000)
        ));
    }

    /**
     * Route protégée.
     * GET /api/me
     */
    @GetMapping("/me")
    public ResponseEntity<Map<String, Object>> me(
            @RequestHeader(value = "Authorization", required = false)
            String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new AuthenticationFailedException("Token manquant ou invalide");
        }
        String token = authHeader.substring(7);
        User user = authService.getUserByToken(token);
        return ResponseEntity.ok(Map.of(
                "email", user.getEmail(),
                "createdAt", user.getCreatedAt().toString()
        ));
    }
}