package com.example.auth_server.service;

import com.example.auth_server.entity.User;
import com.example.auth_server.exception.AuthenticationFailedException;
import com.example.auth_server.exception.InvalidInputException;
import com.example.auth_server.exception.ResourceConflictException;
import com.example.auth_server.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

/**
 * Service principal d'authentification.
 *
 * ATTENTION : Cette implémentation est volontairement dangereuse
 * et ne doit jamais être utilisée en production.
 * TP3 améliore le protocole avec HMAC mais le mot de passe
 * est stocké de façon réversible pour permettre le recalcul HMAC.
 */
@Service
public class AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);
    private static final int MAX_ATTEMPTS = 5;
    private static final int LOCK_DURATION_MINUTES = 2;

    private final UserRepository userRepository;

    public AuthService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /**
     * Inscrit un nouvel utilisateur.
     * Le mot de passe est stocké en clair pour permettre le recalcul HMAC.
     *
     * ATTENTION : Cette implémentation est volontairement dangereuse
     * et ne doit jamais être utilisée en production.
     */
    public User register(String email, String password) {

        if (email == null || email.isBlank()) {
            logger.warn("Inscription échouée : email vide");
            throw new InvalidInputException("L'email ne peut pas être vide");
        }
        if (!email.contains("@")) {
            logger.warn("Inscription échouée : format email invalide");
            throw new InvalidInputException("Format email invalide");
        }

        PasswordPolicyValidator.validate(password);

        if (userRepository.findByEmail(email).isPresent()) {
            logger.warn("Inscription échouée : email déjà existant");
            throw new ResourceConflictException("Cet email est déjà utilisé");
        }

        // TP3 : mot de passe stocké en clair pour recalcul HMAC
        // TP4 corrigera cela avec AES-GCM Master Key
        User user = new User(email, password);
        userRepository.save(user);
        logger.info("Inscription réussie");
        return user;
    }

    /**
     * Récupère un utilisateur par son token.
     */
    public User getUserByToken(String token) {
        return userRepository.findByToken(token)
                .orElseThrow(() -> new AuthenticationFailedException(
                        "Token invalide"));
    }
}