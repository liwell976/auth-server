package com.example.auth_server.controller;

import com.example.auth_server.entity.User;
import com.example.auth_server.exception.AuthenticationFailedException;
import com.example.auth_server.service.AuthService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

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

    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(
            @RequestParam String email,
            @RequestParam String password) {
        String token = authService.login(email, password);
        return ResponseEntity.ok(Map.of(
                "message", "Connexion réussie",
                "token", token
        ));
    }

    @GetMapping("/me")
    public ResponseEntity<Map<String, Object>> me(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {

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