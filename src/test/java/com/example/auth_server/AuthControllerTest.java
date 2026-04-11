package com.example.auth_server;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    // Test controller — Register OK
    @Test
    void testRegisterOK() throws Exception {
        mockMvc.perform(post("/api/auth/register")
                        .param("email", "controller@example.com")
                        .param("password", "Password123!"))
                .andExpect(status().isCreated());
    }

    // Test controller — Register email invalide
    @Test
    void testRegisterEmailInvalide() throws Exception {
        mockMvc.perform(post("/api/auth/register")
                        .param("email", "invalide")
                        .param("password", "Password123!"))
                .andExpect(status().isBadRequest());
    }

    // Test controller — Register email déjà existant
    @Test
    void testRegisterEmailDejaExistant() throws Exception {
        mockMvc.perform(post("/api/auth/register")
                .param("email", "double@example.com")
                .param("password", "Password123!"));

        mockMvc.perform(post("/api/auth/register")
                        .param("email", "double@example.com")
                        .param("password", "Password123!"))
                .andExpect(status().isConflict());
    }

    // Test controller — Login OK
    @Test
    void testLoginOK() throws Exception {
        mockMvc.perform(post("/api/auth/register")
                .param("email", "login@example.com")
                .param("password", "Password123!"));

        mockMvc.perform(post("/api/auth/login")
                        .param("email", "login@example.com")
                        .param("password", "Password123!"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").exists());
    }

    // Test controller — Login KO
    @Test
    void testLoginKO() throws Exception {
        mockMvc.perform(post("/api/auth/register")
                .param("email", "loginfail@example.com")
                .param("password", "Password123!"));

        mockMvc.perform(post("/api/auth/login")
                        .param("email", "loginfail@example.com")
                        .param("password", "Mauvais123!"))
                .andExpect(status().isUnauthorized());
    }

    // Test controller — /api/me sans token
    @Test
    void testMeSansToken() throws Exception {
        mockMvc.perform(get("/api/auth/me"))
                .andExpect(status().isUnauthorized());
    }

    // Test controller — /api/me avec token valide
    @Test
    void testMeAvecToken() throws Exception {
        mockMvc.perform(post("/api/auth/register")
                .param("email", "me@example.com")
                .param("password", "Password123!"));

        String response = mockMvc.perform(post("/api/auth/login")
                        .param("email", "me@example.com")
                        .param("password", "Password123!"))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();

        String token = response.split("\"token\":\"")[1].split("\"")[0];

        mockMvc.perform(get("/api/auth/me")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("me@example.com"));
    }
}