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

    @Column(name = "token")
    private String token;

    public User() {}

    public User(String email, String passwordClear) {
        this.email = email;
        this.passwordClear = passwordClear;
        this.createdAt = LocalDateTime.now();
    }

    // Getters & Setters
    public String getPasswordClear() {
        return passwordClear;
    }

    public void setPasswordClear(String passwordClear) {
        this.passwordClear = passwordClear;
    }

    public Long getId() {
        return id;
    }

    public String getEmail() {
        return email;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public String getToken() { return token; }
    public void setToken(String token) { this.token = token; }
}