package com.example.auth_server.service;

import com.example.auth_server.entity.User;
import com.example.auth_server.exception.AuthenticationFailedException;
import com.example.auth_server.exception.InvalidInputException;
import com.example.auth_server.exception.ResourceConflictException;
import com.example.auth_server.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Service principal d'authentification.
 *
 */
@Service
public class AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);
    private static final int MAX_ATTEMPTS = 5;
    private static final int LOCK_DURATION_MINUTES = 2;

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    public AuthService(UserRepository userRepository) {
        this.userRepository = userRepository;
        this.passwordEncoder = new BCryptPasswordEncoder();
    }

    /**
     * Inscrit un nouvel utilisateur avec mot de passe hashé.
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

        String hashedPassword = passwordEncoder.encode(password);
        User user = new User(email, hashedPassword);
        userRepository.save(user);
        logger.info("Inscription réussie");
        return user;
    }

    /**
     * Vérifie les identifiants avec BCrypt et gestion anti brute force.
     *
     */
    public String login(String email, String password) {

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new AuthenticationFailedException(
                        "Email ou mot de passe incorrect"));

        // Vérification du blocage
        if (user.getLockUntil() != null &&
                user.getLockUntil().isAfter(LocalDateTime.now())) {
            logger.warn("Compte bloqué");
            throw new AuthenticationFailedException(
                    "Compte temporairement bloqué. Réessayez dans 2 minutes.");
        }

        // Vérification du mot de passe
        if (!passwordEncoder.matches(password, user.getPasswordHash())) {
            user.setFailedAttempts(user.getFailedAttempts() + 1);
            if (user.getFailedAttempts() >= MAX_ATTEMPTS) {
                user.setLockUntil(LocalDateTime.now()
                        .plusMinutes(LOCK_DURATION_MINUTES));
                logger.warn("Compte bloqué après {} tentatives", MAX_ATTEMPTS);
            }
            userRepository.save(user);
            logger.warn("Connexion échouée");
            throw new AuthenticationFailedException(
                    "Email ou mot de passe incorrect");
        }

        // Réinitialisation des tentatives
        user.setFailedAttempts(0);
        user.setLockUntil(null);
        String token = UUID.randomUUID().toString();
        user.setToken(token);
        userRepository.save(user);
        logger.info("Connexion réussie");
        return token;
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