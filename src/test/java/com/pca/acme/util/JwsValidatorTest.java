package com.pca.acme.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class JwsValidatorTest {

    private JwsValidator jwsValidator;

    @BeforeEach
    void setUp() {
        jwsValidator = new JwsValidator(new ObjectMapper());
    }

    @Test
    void shouldReturnInvalidForJwsWithWrongNumberOfParts() {
        // Given
        String invalidJws = "header.payload"; // 2개 부분만 있음

        // When
        JwsValidator.JwsValidationResult result = jwsValidator.validateJws(invalidJws);

        // Then
        assertFalse(result.isValid());
        assertEquals("Invalid JWS format: must have 3 parts", result.getErrorMessage());
    }

    @Test
    void shouldReturnInvalidForJwsWithMissingAlg() {
        // Given
        String header = "{\"kid\":\"test-key\"}"; // alg가 없음
        String headerB64 = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(header.getBytes());
        String payloadB64 = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString("payload".getBytes());
        String signatureB64 = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString("signature".getBytes());
        String jws = headerB64 + "." + payloadB64 + "." + signatureB64;

        // When
        JwsValidator.JwsValidationResult result = jwsValidator.validateJws(jws);

        // Then
        assertFalse(result.isValid());
        assertEquals("Missing 'alg' in JWS header", result.getErrorMessage());
    }

    @Test
    void shouldReturnValidForProperlyFormattedJws() {
        // Given
        String header = "{\"alg\":\"RS256\",\"kid\":\"test-key\"}";
        String headerB64 = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(header.getBytes());
        String payloadB64 = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString("test-payload".getBytes());
        String signatureB64 = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString("test-signature".getBytes());
        String jws = headerB64 + "." + payloadB64 + "." + signatureB64;

        // When
        JwsValidator.JwsValidationResult result = jwsValidator.validateJws(jws);

        // Then
        assertTrue(result.isValid());
        assertNull(result.getErrorMessage());
        assertNotNull(result.getHeader());
        assertEquals("RS256", result.getHeader().get("alg"));
        assertEquals("test-key", result.getHeader().get("kid"));
        assertEquals("test-payload", result.getPayload());
    }

    @Test
    void shouldReturnInvalidForMalformedBase64() {
        // Given
        String invalidJws = "invalid-base64.payload.signature";

        // When
        JwsValidator.JwsValidationResult result = jwsValidator.validateJws(invalidJws);

        // Then
        assertFalse(result.isValid());
        assertTrue(result.getErrorMessage().contains("JWS validation error"));
    }

    @Test
    void shouldReturnInvalidForMalformedJsonInHeader() {
        // Given
        String malformedHeader = "{\"alg\":\"RS256\",\"kid\":}"; // 잘못된 JSON
        String headerB64 = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(malformedHeader.getBytes());
        String payloadB64 = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString("payload".getBytes());
        String signatureB64 = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString("signature".getBytes());
        String jws = headerB64 + "." + payloadB64 + "." + signatureB64;

        // When
        JwsValidator.JwsValidationResult result = jwsValidator.validateJws(jws);

        // Then
        assertFalse(result.isValid());
        assertTrue(result.getErrorMessage().contains("JWS validation error"));
    }

    @Test
    void shouldHandleEmptyPayload() {
        // Given
        String header = "{\"alg\":\"RS256\"}";
        String headerB64 = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(header.getBytes());
        String payloadB64 = ""; // 빈 페이로드
        String signatureB64 = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString("signature".getBytes());
        String jws = headerB64 + "." + payloadB64 + "." + signatureB64;

        // When
        JwsValidator.JwsValidationResult result = jwsValidator.validateJws(jws);

        // Then
        assertTrue(result.isValid());
        assertEquals("", result.getPayload());
    }

    @Test
    void shouldHandleSpecialCharactersInPayload() {
        // Given
        String header = "{\"alg\":\"RS256\"}";
        String headerB64 = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(header.getBytes());
        String payload = "{\"key\":\"value\",\"number\":123}";
        String payloadB64 = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(payload.getBytes());
        String signatureB64 = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString("signature".getBytes());
        String jws = headerB64 + "." + payloadB64 + "." + signatureB64;

        // When
        JwsValidator.JwsValidationResult result = jwsValidator.validateJws(jws);

        // Then
        assertTrue(result.isValid());
        assertEquals(payload, result.getPayload());
    }
} 