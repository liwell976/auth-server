package com.example.auth_server.service;

import com.example.auth_server.entity.User;
import com.example.auth_server.exception.AuthenticationFailedException;
import com.example.auth_server.exception.InvalidInputException;
import com.example.auth_server.exception.ResourceConflictException;
import com.example.auth_server.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Service principal d'authentification.
 * * TP4 chiffre les mots de passe avec AES-GCM via Master Key.
 */
@Service

public class AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

    private final UserRepository userRepository;
    private final EncryptionService encryptionService;

    public AuthService(UserRepository userRepository,
                       EncryptionService encryptionService) {
        this.userRepository = userRepository;
        this.encryptionService = encryptionService;
    }

    /**
     * Inscrit un nouvel utilisateur avec mot de passe chiffré AES-GCM.
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

        try {
            String encryptedPassword = encryptionService.encrypt(password);
            User user = new User(email, encryptedPassword);
            userRepository.save(user);
            logger.info("Inscription réussie");
            return user;
        } catch (Exception e) {
            logger.warn("Inscription échouée : erreur chiffrement");
            throw new InvalidInputException("Erreur lors du chiffrement du mot de passe");
        }
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