package com.pca.acme.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pca.acme.service.NonceService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.util.Base64;
import java.util.Map;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.hamcrest.Matchers.containsString;

/**
 * ACME NewAccount API 테스트
 * RFC 8555 §7.3 Account Management 구현 테스트
 */
@SpringBootTest
class ACMEControllerNewAccountTest {

    private MockMvc mockMvc;

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private NonceService nonceService;

    private String validNonce;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).build();
        validNonce = nonceService.createNonce();
    }

    /**
     * 유효한 JWS로 새 계정 생성 성공 테스트
     */
    @Test
    void shouldCreateNewAccountSuccessfully() throws Exception {
        // Given
        String jwsToken = createValidJwsTokenWithNonceAndKey(Map.of(
            "contact", new String[]{"mailto:admin@example.com"},
            "termsOfServiceAgreed", true
        ), validNonce, "test-key-1");

        // When & Then
        MvcResult result = mockMvc.perform(post("/acme/new-account")
                .contentType("application/jose+json")
                .content(jwsToken))
                .andExpect(status().isCreated())
                .andExpect(header().exists("Location"))
                .andExpect(header().exists("Replay-Nonce"))
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.status").value("valid"))
                .andExpect(jsonPath("$.contact[0]").value("mailto:admin@example.com"))
                .andExpect(jsonPath("$.orders").exists())
                .andReturn();

        // Location 헤더 검증
        String locationHeader = result.getResponse().getHeader("Location");
        assertNotNull(locationHeader);
        assertTrue(locationHeader.contains("/acme/acct/"));
    }

    /**
     * 기존 계정 조회 테스트 (동일한 키로 재요청)
     */
    @Test
    void shouldReturnExistingAccountWhenSameKeyUsed() throws Exception {
        // Given - 첫 번째 계정 생성
        String jwsToken1 = createValidJwsTokenWithNonceAndKey(Map.of(
            "contact", new String[]{"mailto:user@example.com"},
            "termsOfServiceAgreed", true
        ), validNonce, "test-key-2");

        MvcResult firstResult = mockMvc.perform(post("/acme/new-account")
                .contentType("application/jose+json")
                .content(jwsToken1))
                .andExpect(status().isCreated())
                .andReturn();

        String firstLocationHeader = firstResult.getResponse().getHeader("Location");

        // 새로운 nonce로 동일한 키를 사용한 두 번째 요청
        String newNonce = nonceService.createNonce();
        String jwsToken2 = createValidJwsTokenWithNonceAndKey(Map.of(
            "contact", new String[]{"mailto:user@example.com"},
            "termsOfServiceAgreed", true
        ), newNonce, "test-key-2");

        // When & Then - 기존 계정 반환 (200 OK)
        mockMvc.perform(post("/acme/new-account")
                .contentType("application/jose+json")
                .content(jwsToken2))
                .andExpect(status().isOk())
                .andExpect(header().string("Location", firstLocationHeader))
                .andExpect(header().exists("Replay-Nonce"))
                .andExpect(jsonPath("$.status").value("valid"))
                .andExpect(jsonPath("$.contact[0]").value("mailto:user@example.com"));
    }

    /**
     * 연락처 정보 없이 계정 생성 테스트
     */
    @Test
    void shouldCreateAccountWithoutContact() throws Exception {
        // Given
        String jwsToken = createValidJwsTokenWithNonceAndKey(Map.of(
            "termsOfServiceAgreed", true
        ), validNonce, "test-key-3");

        // When & Then
        mockMvc.perform(post("/acme/new-account")
                .contentType("application/jose+json")
                .content(jwsToken))
                .andExpect(status().isCreated())
                .andExpect(header().exists("Location"))
                .andExpect(jsonPath("$.status").value("valid"))
                .andExpect(jsonPath("$.contact").isEmpty());
    }

    /**
     * 서비스 약관 동의 없이 계정 생성 시도 테스트
     */
    @Test
    void shouldRejectAccountCreationWithoutTermsAgreement() throws Exception {
        // Given
        String jwsToken = createValidJwsTokenWithNonceAndKey(Map.of(
            "contact", new String[]{"mailto:admin@example.com"},
            "termsOfServiceAgreed", false
        ), validNonce, "test-key-4");

        // When & Then
        mockMvc.perform(post("/acme/new-account")
                .contentType("application/jose+json")
                .content(jwsToken))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType("application/problem+json;charset=UTF-8"))
                .andExpect(jsonPath("$.type").value("urn:ietf:params:acme:error:userActionRequired"))
                .andExpect(jsonPath("$.detail").value("Terms of service agreement is required"));
    }

    /**
     * 잘못된 연락처 형식 테스트
     */
    @Test
    void shouldRejectInvalidContactFormat() throws Exception {
        // Given
        String jwsToken = createValidJwsTokenWithNonceAndKey(Map.of(
            "contact", new String[]{"invalid-contact-format"},
            "termsOfServiceAgreed", true
        ), validNonce, "test-key-5");

        // When & Then
        mockMvc.perform(post("/acme/new-account")
                .contentType("application/jose+json")
                .content(jwsToken))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType("application/problem+json;charset=UTF-8"))
                .andExpect(jsonPath("$.type").value("urn:ietf:params:acme:error:invalidContact"))
                .andExpect(jsonPath("$.detail").value(containsString("Invalid contact")));
    }

    /**
     * 빈 페이로드로 계정 생성 시도 테스트
     */
    @Test
    void shouldRejectEmptyPayload() throws Exception {
        // Given
        String jwsToken = createValidJwsTokenWithNonceAndKey(Map.of(), validNonce, "test-key-6");

        // When & Then
        mockMvc.perform(post("/acme/new-account")
                .contentType("application/jose+json")
                .content(jwsToken))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType("application/problem+json;charset=UTF-8"))
                .andExpect(jsonPath("$.type").value("urn:ietf:params:acme:error:malformed"))
                .andExpect(jsonPath("$.detail").value(containsString("termsOfServiceAgreed")));
    }

    /**
     * JWS 헤더에 jwk 필드가 없는 경우 테스트
     */
    @Test
    void shouldRejectJwsWithoutJwkHeader() throws Exception {
        // Given - jwk 필드 없는 JWS 토큰
        String jwsToken = createJwsTokenWithoutJwk(Map.of(
            "contact", new String[]{"mailto:admin@example.com"},
            "termsOfServiceAgreed", true
        ));

        // When & Then
        mockMvc.perform(post("/acme/new-account")
                .contentType("application/jose+json")
                .content(jwsToken))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType("application/problem+json;charset=UTF-8"))
                .andExpect(jsonPath("$.type").value("urn:ietf:params:acme:error:malformed"))
                .andExpect(jsonPath("$.detail").value(containsString("jwk")));
    }

    /**
     * 잘못된 nonce 사용 테스트
     */
    @Test
    void shouldRejectInvalidNonce() throws Exception {
        // Given
        String jwsToken = createValidJwsTokenWithNonce(Map.of(
            "contact", new String[]{"mailto:admin@example.com"},
            "termsOfServiceAgreed", true
        ), "invalid-nonce");

        // When & Then
        mockMvc.perform(post("/acme/new-account")
                .contentType("application/jose+json")
                .content(jwsToken))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType("application/problem+json;charset=UTF-8"))
                .andExpect(jsonPath("$.type").value("urn:ietf:params:acme:error:badNonce"));
    }

    /**
     * 지원하지 않는 알고리즘 테스트
     */
    @Test
    void shouldRejectUnsupportedAlgorithm() throws Exception {
        // Given
        String jwsToken = createJwsTokenWithAlgorithm(Map.of(
            "contact", new String[]{"mailto:admin@example.com"},
            "termsOfServiceAgreed", true
        ), "HS256"); // 지원하지 않는 알고리즘

        // When & Then
        mockMvc.perform(post("/acme/new-account")
                .contentType("application/jose+json")
                .content(jwsToken))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType("application/problem+json;charset=UTF-8"))
                .andExpect(jsonPath("$.type").value("urn:ietf:params:acme:error:badSignatureAlgorithm"));
    }

    /**
     * 외부 계정 바인딩 테스트
     */
    @Test
    void shouldHandleExternalAccountBinding() throws Exception {
        // Given
        Map<String, Object> externalAccountBinding = Map.of(
            "protected", "eyJhbGciOiJIUzI1NiJ9",
            "payload", "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9",
            "signature", "TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"
        );

        String jwsToken = createValidJwsTokenWithNonceAndKey(Map.of(
            "contact", new String[]{"mailto:admin@example.com"},
            "termsOfServiceAgreed", true,
            "externalAccountBinding", externalAccountBinding
        ), validNonce, "test-key-7");

        // When & Then
        mockMvc.perform(post("/acme/new-account")
                .contentType("application/jose+json")
                .content(jwsToken))
                .andExpect(status().isCreated())
                .andExpect(header().exists("Location"))
                .andExpect(jsonPath("$.status").value("valid"));
    }

    // Helper methods for creating test JWS tokens

    private String createValidJwsToken(Map<String, Object> payload) {
        return createValidJwsTokenWithNonce(payload, validNonce);
    }

    private String createValidJwsTokenWithNonce(Map<String, Object> payload, String nonce) {
        return createValidJwsTokenWithNonceAndKey(payload, nonce, "default-key");
    }

    private String createValidJwsTokenWithNonceAndKey(Map<String, Object> payload, String nonce, String keyId) {
        try {
            // Mock JWK (공개키) - keyId에 따라 다른 키 생성
            Map<String, Object> jwk = Map.of(
                "kty", "RSA",
                "n", "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw" + keyId,
                "e", "AQAB"
            );

            // Protected header
            Map<String, Object> protectedHeader = Map.of(
                "alg", "RS256",
                "jwk", jwk,
                "nonce", nonce,
                "url", "https://localhost:8443/acme/new-account"
            );

            String protectedB64 = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(objectMapper.writeValueAsString(protectedHeader).getBytes());
            String payloadB64 = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(objectMapper.writeValueAsString(payload).getBytes());
            String signature = "mock-signature"; // 테스트용 모의 서명

            // Flattened JSON Serialization (ACME 표준)
            Map<String, Object> jws = Map.of(
                "protected", protectedB64,
                "payload", payloadB64,
                "signature", signature
            );

            return objectMapper.writeValueAsString(jws);
        } catch (Exception e) {
            throw new RuntimeException("Failed to create JWS token", e);
        }
    }

    private String createJwsTokenWithoutJwk(Map<String, Object> payload) {
        try {
            // Protected header without jwk
            Map<String, Object> protectedHeader = Map.of(
                "alg", "RS256",
                "nonce", validNonce,
                "url", "https://localhost:8443/acme/new-account"
            );

            String protectedB64 = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(objectMapper.writeValueAsString(protectedHeader).getBytes());
            String payloadB64 = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(objectMapper.writeValueAsString(payload).getBytes());

            Map<String, Object> jws = Map.of(
                "protected", protectedB64,
                "payload", payloadB64,
                "signature", "mock-signature"
            );

            return objectMapper.writeValueAsString(jws);
        } catch (Exception e) {
            throw new RuntimeException("Failed to create JWS token without jwk", e);
        }
    }

    private String createJwsTokenWithAlgorithm(Map<String, Object> payload, String algorithm) {
        try {
            Map<String, Object> jwk = Map.of(
                "kty", "RSA",
                "n", "test-key",
                "e", "AQAB"
            );

            Map<String, Object> protectedHeader = Map.of(
                "alg", algorithm,
                "jwk", jwk,
                "nonce", validNonce,
                "url", "https://localhost:8443/acme/new-account"
            );

            String protectedB64 = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(objectMapper.writeValueAsString(protectedHeader).getBytes());
            String payloadB64 = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(objectMapper.writeValueAsString(payload).getBytes());

            Map<String, Object> jws = Map.of(
                "protected", protectedB64,
                "payload", payloadB64,
                "signature", "mock-signature"
            );

            return objectMapper.writeValueAsString(jws);
        } catch (Exception e) {
            throw new RuntimeException("Failed to create JWS token with algorithm", e);
        }
    }
} 