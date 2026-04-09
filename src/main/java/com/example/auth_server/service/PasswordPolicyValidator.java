package com.example.auth_server.service;

import com.example.auth_server.exception.InvalidInputException;

/**
 * Validateur de politique de mot de passe.
 *
 * Règles :
 * - 12 caractères minimum
 * - 1 majuscule
 * - 1 minuscule
 * - 1 chiffre
 * - 1 caractère spécial
 * TP2 améliore le stockage mais ne protège pas encore contre le rejeu.
 */
public class PasswordPolicyValidator {

    /**
     * Valide le mot de passe selon la politique définie.
     * Lève une InvalidInputException si le mot de passe ne respecte pas les règles.
     */
    public static void validate(String password) {
        if (password == null || password.length() < 12) {
            throw new InvalidInputException(
                    "Le mot de passe doit contenir au moins 12 caractères");
        }
        if (!password.matches(".*[A-Z].*")) {
            throw new InvalidInputException(
                    "Le mot de passe doit contenir au moins une majuscule");
        }
        if (!password.matches(".*[a-z].*")) {
            throw new InvalidInputException(
                    "Le mot de passe doit contenir au moins une minuscule");
        }
        if (!password.matches(".*[0-9].*")) {
            throw new InvalidInputException(
                    "Le mot de passe doit contenir au moins un chiffre");
        }
        if (!password.matches(".*[^a-zA-Z0-9].*")) {
            throw new InvalidInputException(
                    "Le mot de passe doit contenir au moins un caractère spécial");
        }
    }
}