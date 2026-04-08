package com.example.auth_server.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String email;

    // TP1 Volontairement dangereux : mot de passe en clair
    private String passwordClear;

    private LocalDateTime createdAt;

    public User() {}

    public User(String email, String passwordClear) {
        this.email = email;
        this.passwordClear = passwordClear;
        this.createdAt = LocalDateTime.now();
    }

    // Getters & Setters
}