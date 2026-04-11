package com.example.auth_server.service;

import com.example.auth_server.exception.InvalidInputException;

/**
 * Validateur de politique de mot de passe.
 *
 * TP2 améliore le stockage mais ne protège pas encore contre le rejeu.
 */
public class PasswordPolicyValidator {

    private PasswordPolicyValidator() {}

    /**
     * Valide le mot de passe selon la politique définie.
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
            if (Character.isUpperCase(c)) hasUpper = true;
            else if (Character.isLowerCase(c)) hasLower = true;
            else if (Character.isDigit(c)) hasDigit = true;
            else hasSpecial = true;
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