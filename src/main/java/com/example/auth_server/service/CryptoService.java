package com.example.auth_server.service;

import com.example.auth_server.entity.AuthNonce;
import com.example.auth_server.entity.User;
import com.example.auth_server.exception.AuthenticationFailedException;
import com.example.auth_server.repository.AuthNonceRepository;
import com.example.auth_server.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import java.time.Instant;
import java.util.UUID;

/**
 * Service de vérification du protocole HMAC.
 * Le mot de passe est stocké de façon réversible pour permettre
 * le recalcul du HMAC côté serveur.
 */
@Service
public class CryptoService {

    private static final Logger logger = LoggerFactory.getLogger(CryptoService.class);
    private static final long TIMESTAMP_WINDOW = 60;

    private final UserRepository userRepository;
    private final AuthNonceRepository authNonceRepository;

    public CryptoService(UserRepository userRepository,
                         AuthNonceRepository authNonceRepository) {
        this.userRepository = userRepository;
        this.authNonceRepository = authNonceRepository;
    }

    /**
     * Vérifie la preuve HMAC et retourne un token SSO si valide.
     */
    public String verifyHmacAndLogin(String email, String nonce,
                                     long timestamp, String hmac) {

        // 1. Vérifier que l'email existe
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    logger.warn("Login HMAC échoué : email inconnu");
                    return new AuthenticationFailedException(
                            "Email ou mot de passe incorrect");
                });

        // 2. Vérifier le timestamp ±60 secondes
        long now = Instant.now().getEpochSecond();
        if (Math.abs(now - timestamp) > TIMESTAMP_WINDOW) {
            logger.warn("Login HMAC échoué : timestamp expiré");
            throw new AuthenticationFailedException(
                    "Requête expirée");
        }

        // 3. Vérifier le nonce anti-rejeu
        authNonceRepository.findByUserIdAndNonce(user.getId(), nonce)
                .ifPresent(n -> {
                    throw new AuthenticationFailedException(
                            "Nonce déjà utilisé");
                });

        // 4. Enregistrer le nonce
        AuthNonce authNonce = new AuthNonce(user.getId(), nonce);
        authNonceRepository.save(authNonce);

        // 5. Recalculer le HMAC côté serveur
        try {
            String message = email + ":" + nonce + ":" + timestamp;
            String expectedHmac = HmacUtil.compute(
                    user.getPasswordEncrypted(), message);

            if (!HmacUtil.compareConstantTime(expectedHmac, hmac)) {
                logger.warn("Login HMAC échoué : signature invalide");
                throw new AuthenticationFailedException(
                        "Email ou mot de passe incorrect");
            }
        } catch (AuthenticationFailedException e) {
            throw e;
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new AuthenticationFailedException(
                    "Erreur lors de la vérification");
        }

        // 7. Marquer le nonce comme consommé
        authNonceRepository.findByUserIdAndNonce(user.getId(), nonce)
                .ifPresent(n -> {
                    n.setConsumed(true);
                    authNonceRepository.save(n);
                });

        // 8. Générer et retourner le token SSO
        String token = UUID.randomUUID().toString();
        user.setToken(token);
        userRepository.save(user);
        logger.info("Login HMAC réussi");
        return token;
    }
}