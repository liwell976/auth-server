package com.example.auth_server.service;

import com.example.auth_server.exception.InvalidInputException;

/**
 * Validateur de politique de mot de passe.
 */
public class PasswordPolicyValidator {

    private PasswordPolicyValidator() {}

    /**
     * Valide le mot de passe selon la politique définie.
     * Règles : 12 caractères min, 1 majuscule, 1 minuscule, 1 chiffre, 1 spécial.
     */
    public static void validate(String password) {
        if (password == null || password.length() < 12) {
            throw new InvalidInputException(
                    "Le mot de passe doit contenir au moins 12 caractères");
        }

        boolean hasUpper = false;
        boolean hasLower = false;
        boolean hasDigit = false;
        boolean hasSpecial = false;

        for (char c : password.toCharArray()) {
            if (Character.isUpperCase(c)) {
                hasUpper = true;
            } else if (Character.isLowerCase(c)) {
                hasLower = true;
            } else if (Character.isDigit(c)) {
                hasDigit = true;
            } else if (!Character.isLetterOrDigit(c)) {
                hasSpecial = true;
            }
        }

        if (!hasUpper) {
            throw new InvalidInputException(
                    "Le mot de passe doit contenir au moins une majuscule");
        }
        if (!hasLower) {
            throw new InvalidInputException(
                    "Le mot de passe doit contenir au moins une minuscule");
        }
        if (!hasDigit) {
            throw new InvalidInputException(
                    "Le mot de passe doit contenir au moins un chiffre");
        }
        if (!hasSpecial) {
            throw new InvalidInputException(
                    "Le mot de passe doit contenir au moins un caractère spécial");
        }
    }
}