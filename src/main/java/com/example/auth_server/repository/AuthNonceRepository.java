package com.example.auth_server.repository;

import com.example.auth_server.entity.AuthNonce;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

/**
 * Repository JPA pour l'entité AuthNonce.
 *
 */
public interface AuthNonceRepository extends JpaRepository<AuthNonce, Long> {
    Optional<AuthNonce> findByUserIdAndNonce(Long userId, String nonce);
}