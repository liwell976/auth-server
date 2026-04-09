package com.example.auth_server.controller;

import com.example.auth_server.service.AuthService;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/register")
    public String register(@RequestParam String email,
                           @RequestParam String password) {
        authService.register(email, password);
        return "User registered";
    }

    @PostMapping("/login")
    public String login(@RequestParam String email,
                        @RequestParam String password) {
        boolean success = authService.login(email, password);
        if (!success) {
            return "Login failed";
        }
        return "Login success";
    }

}