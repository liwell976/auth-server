package com.example.auth_server.service;

import com.example.auth_server.entity.User;
import com.example.auth_server.exception.InvalidInputException;
import com.example.auth_server.exception.ResourceConflictException;
import com.example.auth_server.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;


@Service
public class AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

    private final UserRepository userRepository;

    public AuthService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /**
     * Inscrit un nouvel utilisateur.
     * Validation minimale : email non vide, mot de passe minimum 4 caractères.
     */
    public User register(String email, String password) {

        // Validation email
        if (email == null || email.isBlank()) {
            logger.warn("Inscription échouée : email vide");
            throw new InvalidInputException("L'email ne peut pas être vide");
        }
        if (!email.contains("@")) {
            logger.warn("Inscription échouée : format email invalide");
            throw new InvalidInputException("Format email invalide");
        }

        // Validation mot de passe (volontairement faible pour TP1)
        if (password == null || password.length() < 4) {
            logger.warn("Inscription échouée : mot de passe trop court");
            throw new InvalidInputException("Le mot de passe doit faire au moins 4 caractères");
        }

        // Vérification unicité email
        if (userRepository.findByEmail(email).isPresent()) {
            logger.warn("Inscription échouée : email déjà existant - {}", email);
            throw new ResourceConflictException("Cet email est déjà utilisé");
        }

        User user = new User(email, password);
        userRepository.save(user);
        logger.info("Inscription réussie pour : {}", email);
        return user;
    }
    public boolean login(String email, String password) {
        boolean success = userRepository.findByEmail(email)
                .map(user -> user.getPasswordClear().equals(password))
                .orElse(false);

        if (success) {
            logger.info("Connexion réussie pour : {}", email);
        } else {
            logger.warn("Connexion échouée pour : {}", email);
        }

        return success;
    }
}