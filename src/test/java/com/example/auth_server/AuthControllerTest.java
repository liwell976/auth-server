package com.example.auth_server;

import com.example.auth_server.service.HmacUtil;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional
@ActiveProfiles("test")
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

    // Test controller — Login OK avec HMAC
    @Test
    void testLoginOK() throws Exception {
        mockMvc.perform(post("/api/auth/register")
                .param("email", "login@example.com")
                .param("password", "Password123!"));

        String nonce = UUID.randomUUID().toString();
        long timestamp = Instant.now().getEpochSecond();
        String message = "login@example.com:" + nonce + ":" + timestamp;
        String hmac = HmacUtil.compute("Password123!", message);

        String body = String.format(
                "{\"email\":\"login@example.com\",\"nonce\":\"%s\",\"timestamp\":%d,\"hmac\":\"%s\"}",
                nonce, timestamp, hmac);

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists());
    }

    // Test controller — Login KO avec HMAC invalide
    @Test
    void testLoginKO() throws Exception {
        mockMvc.perform(post("/api/auth/register")
                .param("email", "loginfail@example.com")
                .param("password", "Password123!"));

        String nonce = UUID.randomUUID().toString();
        long timestamp = Instant.now().getEpochSecond();

        String body = String.format(
                "{\"email\":\"loginfail@example.com\",\"nonce\":\"%s\",\"timestamp\":%d,\"hmac\":\"hmac_invalide\"}",
                nonce, timestamp);

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
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

        String nonce = UUID.randomUUID().toString();
        long timestamp = Instant.now().getEpochSecond();
        String message = "me@example.com:" + nonce + ":" + timestamp;
        String hmac = HmacUtil.compute("Password123!", message);

        String body = String.format(
                "{\"email\":\"me@example.com\",\"nonce\":\"%s\",\"timestamp\":%d,\"hmac\":\"%s\"}",
                nonce, timestamp, hmac);

        String response = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();

        String token = response.split("\"accessToken\":\"")[1].split("\"")[0];

        mockMvc.perform(get("/api/auth/me")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("me@example.com"));
    }
}