package com.example.auth_server.service;

import com.example.auth_server.exception.InvalidInputException;

/**
 * Validateur de politique de mot de passe.
 * Règles imposées :
 * - 12 caractères minimum
 * - 1 majuscule minimum
 * - 1 minuscule minimum
 * - 1 chiffre minimum
 * - 1 caractère spécial minimum
 * ATTENTION : Cette implémentation est volontairement dangereuse
 * et ne doit jamais être utilisée en production.
 */
public class PasswordPolicyValidator {

    private PasswordPolicyValidator() {}

    /**
     * Valide le mot de passe selon la politique définie.
     * Lève une InvalidInputException si le mot de passe ne respecte pas les règles.
     *
     * @param password le mot de passe à valider
     * @throws InvalidInputException si le mot de passe est invalide
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
            if (hasUpper && hasLower && hasDigit && hasSpecial) {
                break;
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