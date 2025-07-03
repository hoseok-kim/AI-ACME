package com.pca.acme.controller;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pca.acme.service.NonceService;

@SpringBootTest
class ACMEControllerNewOrderTest {

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    private NonceService nonceService;

    private MockMvc mockMvc;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).build();
        objectMapper = new ObjectMapper();
    }

    private String createValidJwsToken(String kidUrl, Map<String, Object> payload) {
        String nonce = nonceService.createNonce();

        Map<String, Object> protectedHeader = Map.of(
            "alg", "RS256",
            "kid", kidUrl,
            "nonce", nonce,
            "url", "https://localhost:8443/acme/new-order"
        );

        try {
            String protectedHeaderJson = objectMapper.writeValueAsString(protectedHeader);
            String payloadJson = objectMapper.writeValueAsString(payload);

            String protectedHeaderEncoded = java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString(protectedHeaderJson.getBytes());
            String payloadEncoded = java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString(payloadJson.getBytes());

            String signature = "dummy-signature";

            return String.format("{\"protected\":\"%s\",\"payload\":\"%s\",\"signature\":\"%s\"}",
                protectedHeaderEncoded, payloadEncoded, signature);
        } catch (Exception e) {
            throw new RuntimeException("Failed to create JWS token", e);
        }
    }

    /**
     * 테스트용 계정을 생성합니다.
     */
    private String createTestAccount(String accountId) throws Exception {
        // 테스트용 JWK 생성
        Map<String, Object> jwk = Map.of(
            "kty", "RSA",
            "n", "test-n-" + accountId,
            "e", "AQAB"
        );

        String nonce = nonceService.createNonce();
        Map<String, Object> protectedHeader = Map.of(
            "alg", "RS256",
            "jwk", jwk,
            "nonce", nonce,
            "url", "https://localhost:8443/acme/new-account"
        );

        Map<String, Object> payload = Map.of(
            "termsOfServiceAgreed", true,
            "contact", List.of("mailto:test@example.com")
        );

        String protectedHeaderJson = objectMapper.writeValueAsString(protectedHeader);
        String payloadJson = objectMapper.writeValueAsString(payload);

        String protectedHeaderEncoded = java.util.Base64.getUrlEncoder().withoutPadding()
            .encodeToString(protectedHeaderJson.getBytes());
        String payloadEncoded = java.util.Base64.getUrlEncoder().withoutPadding()
            .encodeToString(payloadJson.getBytes());

        String signature = "dummy-signature";
        String jwsToken = String.format("{\"protected\":\"%s\",\"payload\":\"%s\",\"signature\":\"%s\"}",
            protectedHeaderEncoded, payloadEncoded, signature);

        // 계정 생성 요청
        var result = mockMvc.perform(post("/acme/new-account")
                .contentType("application/jose+json")
                .content(jwsToken))
                .andExpect(status().isCreated())
                .andReturn();

        return result.getResponse().getHeader("Location");
    }

    @Test
    void shouldCreateNewOrderSuccessfully() throws Exception {
        String kidUrl = createTestAccount("123");
        Map<String, Object> payload = Map.of(
            "identifiers", List.of(
                Map.of("type", "dns", "value", "example.com")
            )
        );
        String jwsToken = createValidJwsToken(kidUrl, payload);

        mockMvc.perform(post("/acme/new-order")
                .contentType("application/jose+json")
                .content(jwsToken))
                .andExpect(status().isCreated())
                .andExpect(header().exists("Location"))
                .andExpect(header().exists("Replay-Nonce"))
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.status").value("pending"))
                .andExpect(jsonPath("$.expires").exists())
                .andExpect(jsonPath("$.identifiers").isArray())
                .andExpect(jsonPath("$.identifiers[0].type").value("dns"))
                .andExpect(jsonPath("$.identifiers[0].value").value("example.com"))
                .andExpect(jsonPath("$.authorizations").isArray())
                .andExpect(jsonPath("$.authorizations").isNotEmpty())
                .andExpect(jsonPath("$.finalize").exists());
    }

    @Test
    void shouldFailWhenIdentifiersAreMissing() throws Exception {
        String kidUrl = createTestAccount("124");
        Map<String, Object> payload = Map.of();
        String jwsToken = createValidJwsToken(kidUrl, payload);

        mockMvc.perform(post("/acme/new-order")
                .contentType("application/jose+json")
                .content(jwsToken))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.type").value("urn:ietf:params:acme:error:malformed"));
    }

    @Test
    void shouldFailWhenAccountNotFound() throws Exception {
        String kidUrl = "https://localhost:8443/acme/account/nonexistent";
        Map<String, Object> payload = Map.of(
            "identifiers", List.of(
                Map.of("type", "dns", "value", "example.com")
            )
        );
        String jwsToken = createValidJwsToken(kidUrl, payload);

        mockMvc.perform(post("/acme/new-order")
                .contentType("application/jose+json")
                .content(jwsToken))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.type").value("urn:ietf:params:acme:error:accountDoesNotExist"));
    }
}