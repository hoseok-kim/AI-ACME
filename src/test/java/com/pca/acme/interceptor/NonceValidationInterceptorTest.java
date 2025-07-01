package com.pca.acme.interceptor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pca.acme.service.NonceService;

@ExtendWith(MockitoExtension.class)
class NonceValidationInterceptorTest {

    @Mock
    private NonceService nonceService;

    private NonceValidationInterceptor interceptor;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    @BeforeEach
    void setUp() {
        ObjectMapper objectMapper = new ObjectMapper();
        interceptor = new NonceValidationInterceptor(nonceService, objectMapper);
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
    }

    @Test
    void shouldSkipValidationForDirectoryEndpoint() throws Exception {
        // Given
        request.setRequestURI("/acme/directory");

        // When
        boolean result = interceptor.preHandle(request, response, null);

        // Then
        assertTrue(result);
        verifyNoInteractions(nonceService);
    }

    @Test
    void shouldSkipValidationForNewNonceEndpoint() throws Exception {
        // Given
        request.setRequestURI("/acme/new-nonce");

        // When
        boolean result = interceptor.preHandle(request, response, null);

        // Then
        assertTrue(result);
        verifyNoInteractions(nonceService);
    }

    @Test
    void shouldSkipValidationForNonAcmeEndpoint() throws Exception {
        // Given
        request.setRequestURI("/api/health");

        // When
        boolean result = interceptor.preHandle(request, response, null);

        // Then
        assertTrue(result);
        verifyNoInteractions(nonceService);
    }

    @Test
    void shouldReturnErrorWhenJwsHeaderNotFound() throws Exception {
        // Given
        request.setRequestURI("/acme/new-account");
        // JWS header가 request attribute에 없음

        // When
        boolean result = interceptor.preHandle(request, response, null);

        // Then
        assertFalse(result);
        assertEquals(400, response.getStatus());
        assertEquals("application/problem+json;charset=UTF-8", response.getContentType());
        assertTrue(response.getContentAsString().contains("malformed"));
        assertTrue(response.getContentAsString().contains("JWS header information is missing"));
    }

    @Test
    void shouldReturnErrorWhenNonceIsMissing() throws Exception {
        // Given
        request.setRequestURI("/acme/new-account");
        Map<String, Object> jwsHeader = Map.of(
            "alg", "RS256",
            "jwk", Map.of("kty", "RSA")
        );
        request.setAttribute("jwsHeader", jwsHeader);

        // When
        boolean result = interceptor.preHandle(request, response, null);

        // Then
        assertFalse(result);
        assertEquals(400, response.getStatus());
        assertEquals("application/problem+json;charset=UTF-8", response.getContentType());
        assertTrue(response.getContentAsString().contains("badNonce"));
        assertTrue(response.getContentAsString().contains("Missing 'nonce' field in JWS header"));
    }

    @Test
    void shouldReturnErrorWhenNonceIsEmpty() throws Exception {
        // Given
        request.setRequestURI("/acme/new-account");
        Map<String, Object> jwsHeader = Map.of(
            "alg", "RS256",
            "jwk", Map.of("kty", "RSA"),
            "nonce", ""
        );
        request.setAttribute("jwsHeader", jwsHeader);

        // When
        boolean result = interceptor.preHandle(request, response, null);

        // Then
        assertFalse(result);
        assertEquals(400, response.getStatus());
        assertEquals("application/problem+json;charset=UTF-8", response.getContentType());
        assertTrue(response.getContentAsString().contains("badNonce"));
        assertTrue(response.getContentAsString().contains("Missing 'nonce' field in JWS header"));
    }

    @Test
    void shouldReturnErrorWhenNonceIsWhitespace() throws Exception {
        // Given
        request.setRequestURI("/acme/new-account");
        Map<String, Object> jwsHeader = Map.of(
            "alg", "RS256",
            "jwk", Map.of("kty", "RSA"),
            "nonce", "   "
        );
        request.setAttribute("jwsHeader", jwsHeader);

        // When
        boolean result = interceptor.preHandle(request, response, null);

        // Then
        assertFalse(result);
        assertEquals(400, response.getStatus());
        assertEquals("application/problem+json;charset=UTF-8", response.getContentType());
        assertTrue(response.getContentAsString().contains("badNonce"));
        assertTrue(response.getContentAsString().contains("Missing 'nonce' field in JWS header"));
    }

    @Test
    void shouldReturnErrorWhenNonceValidationFails() throws Exception {
        // Given
        request.setRequestURI("/acme/new-account");
        String testNonce = "invalid-nonce";
        Map<String, Object> jwsHeader = Map.of(
            "alg", "RS256",
            "jwk", Map.of("kty", "RSA"),
            "nonce", testNonce
        );
        request.setAttribute("jwsHeader", jwsHeader);

        when(nonceService.validateAndConsumeNonce(testNonce)).thenReturn(false);

        // When
        boolean result = interceptor.preHandle(request, response, null);

        // Then
        assertFalse(result);
        assertEquals(400, response.getStatus());
        assertEquals("application/problem+json;charset=UTF-8", response.getContentType());
        assertTrue(response.getContentAsString().contains("badNonce"));
        assertTrue(response.getContentAsString().contains("Invalid or expired nonce"));
        verify(nonceService).validateAndConsumeNonce(testNonce);
    }

    @Test
    void shouldSucceedWhenNonceValidationPasses() throws Exception {
        // Given
        request.setRequestURI("/acme/new-account");
        String testNonce = "valid-nonce-123";
        Map<String, Object> jwsHeader = Map.of(
            "alg", "RS256",
            "jwk", Map.of("kty", "RSA"),
            "nonce", testNonce
        );
        request.setAttribute("jwsHeader", jwsHeader);

        when(nonceService.validateAndConsumeNonce(testNonce)).thenReturn(true);

        // When
        boolean result = interceptor.preHandle(request, response, null);

        // Then
        assertTrue(result);
        assertEquals(200, response.getStatus());
        verify(nonceService).validateAndConsumeNonce(testNonce);
    }

    @Test
    void shouldValidateNonceForOtherAcmeEndpoints() throws Exception {
        // Given
        request.setRequestURI("/acme/revoke-cert");
        String testNonce = "valid-nonce-456";
        Map<String, Object> jwsHeader = Map.of(
            "alg", "RS256",
            "kid", "https://example.com/acme/account/123",
            "nonce", testNonce
        );
        request.setAttribute("jwsHeader", jwsHeader);

        when(nonceService.validateAndConsumeNonce(testNonce)).thenReturn(true);

        // When
        boolean result = interceptor.preHandle(request, response, null);

        // Then
        assertTrue(result);
        assertEquals(200, response.getStatus());
        verify(nonceService).validateAndConsumeNonce(testNonce);
    }

    @Test
    void shouldHandleNullNonceInHeader() throws Exception {
        // Given
        request.setRequestURI("/acme/new-account");
        Map<String, Object> jwsHeader = new java.util.HashMap<>();
        jwsHeader.put("alg", "RS256");
        jwsHeader.put("jwk", Map.of("kty", "RSA"));
        jwsHeader.put("nonce", null);  // explicitly null
        request.setAttribute("jwsHeader", jwsHeader);

        // When
        boolean result = interceptor.preHandle(request, response, null);

        // Then
        assertFalse(result);
        assertEquals(400, response.getStatus());
        assertTrue(response.getContentAsString().contains("badNonce"));
        assertTrue(response.getContentAsString().contains("Missing 'nonce' field in JWS header"));
        verifyNoInteractions(nonceService);
    }
}