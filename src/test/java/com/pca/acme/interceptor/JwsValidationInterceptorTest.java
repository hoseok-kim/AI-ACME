package com.pca.acme.interceptor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pca.acme.service.NonceService;
import com.pca.acme.util.JwsValidator;

@ExtendWith(MockitoExtension.class)
class JwsValidationInterceptorTest {

    @Mock
    private JwsValidator jwsValidator;

    @Mock
    private NonceService nonceService;

    private JwsValidationInterceptor interceptor;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    @BeforeEach
    void setUp() {
        interceptor = new JwsValidationInterceptor(jwsValidator, new ObjectMapper());
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
    }

    @Test
    void shouldSkipJwsValidationForDirectoryEndpoint() throws Exception {
        // Given
        request.setRequestURI("/acme/directory");
        request.setMethod("GET");

        // When
        boolean result = interceptor.preHandle(request, response, null);

        // Then
        assertTrue(result);
        assertEquals(HttpStatus.OK.value(), response.getStatus());
        verifyNoInteractions(jwsValidator);
    }

    @Test
    void shouldSkipJwsValidationForNewNonceEndpoint() throws Exception {
        // Given
        request.setRequestURI("/acme/new-nonce");
        request.setMethod("HEAD");

        // When
        boolean result = interceptor.preHandle(request, response, null);

        // Then
        assertTrue(result);
        assertEquals(HttpStatus.OK.value(), response.getStatus());
        verifyNoInteractions(jwsValidator);
    }

    @Test
    void shouldSkipJwsValidationForNonAcmePaths() throws Exception {
        // Given
        request.setRequestURI("/api/other");
        request.setMethod("POST");

        // When
        boolean result = interceptor.preHandle(request, response, null);

        // Then
        assertTrue(result);
        assertEquals(HttpStatus.OK.value(), response.getStatus());
        verifyNoInteractions(jwsValidator);
    }

    @Test
    void shouldReturnErrorWhenContentTypeIsNotJoseJson() throws Exception {
        // Given
        request.setRequestURI("/acme/new-account");
        request.setMethod("POST");
        request.setContentType("application/json");

        // When
        boolean result = interceptor.preHandle(request, response, null);

        // Then
        assertFalse(result);
        assertEquals(HttpStatus.BAD_REQUEST.value(), response.getStatus());
        assertTrue(response.getContentAsString().contains("missing-jws"));
        verifyNoInteractions(jwsValidator);
    }

    @Test
    void shouldReturnErrorWhenJwsTokenIsMissing() throws Exception {
        // Given
        request.setRequestURI("/acme/new-account");
        request.setMethod("POST");
        request.setContentType("application/jose+json");
        // 빈 본문

        // When
        boolean result = interceptor.preHandle(request, response, null);

        // Then
        assertFalse(result);
        assertEquals(HttpStatus.BAD_REQUEST.value(), response.getStatus());
        assertTrue(response.getContentAsString().contains("missing-jws"));
        verifyNoInteractions(jwsValidator);
    }

    @Test
    void shouldReturnErrorWhenJwsValidationFails() throws Exception {
        // Given
        request.setRequestURI("/acme/new-account");
        request.setMethod("POST");
        request.setContentType("application/jose+json");
        request.setContent("invalid.jws.token".getBytes());

        when(jwsValidator.validateJws(anyString()))
                .thenReturn(JwsValidator.JwsValidationResult.invalid("Invalid JWS format"));

        // When
        boolean result = interceptor.preHandle(request, response, null);

        // Then
        assertFalse(result);
        assertEquals(HttpStatus.BAD_REQUEST.value(), response.getStatus());
        assertTrue(response.getContentAsString().contains("malformed-jws"));
        verify(jwsValidator).validateJws("invalid.jws.token");
    }

    @Test
    void shouldPassJwsValidationWhenValid() throws Exception {
        // Given
        request.setRequestURI("/acme/new-account");
        request.setMethod("POST");
        request.setContentType("application/jose+json");
        request.setContent("valid.jws.token".getBytes());

        Map<String, Object> mockHeader = Map.of(
            "alg", "RS256",
            "jwk", Map.of("kty", "RSA", "n", "test", "e", "AQAB"),
            "nonce", "test-nonce",
            "url", "https://localhost:8443/acme/new-account"
        );
        when(jwsValidator.validateJws(anyString()))
                .thenReturn(JwsValidator.JwsValidationResult.valid(mockHeader, "payload"));

        // When
        boolean result = interceptor.preHandle(request, response, null);

        // Then
        assertTrue(result);
        assertEquals(HttpStatus.OK.value(), response.getStatus());
        verify(jwsValidator).validateJws("valid.jws.token");

        // 검증된 JWS 정보가 요청 속성에 저장되었는지 확인
        assertEquals(mockHeader, request.getAttribute("jwsHeader"));
        assertEquals("payload", request.getAttribute("jwsPayload"));
    }

    @Test
    void shouldFailWhenNewAccountJwsMissingJwkField() throws Exception {
        // Given
        request.setRequestURI("/acme/new-account");
        request.setMethod("POST");
        request.setContentType("application/jose+json");
        request.setContent("valid.jws.token".getBytes());

        Map<String, Object> mockHeader = Map.of(
            "alg", "RS256",
            "nonce", "test-nonce",
            "url", "https://localhost:8443/acme/new-account"
            // jwk 필드 누락
        );
        when(jwsValidator.validateJws(anyString()))
                .thenReturn(JwsValidator.JwsValidationResult.valid(mockHeader, "payload"));

        // When
        boolean result = interceptor.preHandle(request, response, null);

        // Then
        assertFalse(result);
        assertEquals(HttpStatus.BAD_REQUEST.value(), response.getStatus());
        assertTrue(response.getContentAsString().contains("malformed"));
        assertTrue(response.getContentAsString().contains("Missing 'jwk' field"));
    }

    @Test
    void shouldFailWhenNewAccountJwsHasUnsupportedAlgorithm() throws Exception {
        // Given
        request.setRequestURI("/acme/new-account");
        request.setMethod("POST");
        request.setContentType("application/jose+json");
        request.setContent("valid.jws.token".getBytes());

        Map<String, Object> mockHeader = Map.of(
            "alg", "HS256", // 지원하지 않는 알고리즘
            "jwk", Map.of("kty", "RSA", "n", "test", "e", "AQAB"),
            "nonce", "test-nonce",
            "url", "https://localhost:8443/acme/new-account"
        );
        when(jwsValidator.validateJws(anyString()))
                .thenReturn(JwsValidator.JwsValidationResult.valid(mockHeader, "payload"));

        // When
        boolean result = interceptor.preHandle(request, response, null);

        // Then
        assertFalse(result);
        assertEquals(HttpStatus.BAD_REQUEST.value(), response.getStatus());
        assertTrue(response.getContentAsString().contains("badSignatureAlgorithm"));
    }

    @Test
    void shouldFailWhenNewAccountJwsHasInvalidUrl() throws Exception {
        // Given
        request.setRequestURI("/acme/new-account");
        request.setMethod("POST");
        request.setContentType("application/jose+json");
        request.setContent("valid.jws.token".getBytes());

        Map<String, Object> mockHeader = Map.of(
            "alg", "RS256",
            "jwk", Map.of("kty", "RSA", "n", "test", "e", "AQAB"),
            "nonce", "test-nonce",
            "url", "https://localhost:8443/acme/wrong-url"  // 잘못된 URL
        );
        when(jwsValidator.validateJws(anyString()))
                .thenReturn(JwsValidator.JwsValidationResult.valid(mockHeader, "payload"));

        // When
        boolean result = interceptor.preHandle(request, response, null);

        // Then
        assertFalse(result);
        assertEquals(HttpStatus.BAD_REQUEST.value(), response.getStatus());
        assertTrue(response.getContentAsString().contains("malformed"));
        assertTrue(response.getContentAsString().contains("Invalid or missing 'url' field"));
    }

    @Test
    void shouldHandleIOExceptionGracefully() throws Exception {
        // Given
        request.setRequestURI("/acme/new-account");
        request.setMethod("POST");
        request.setContentType("application/jose+json");

        // IOException을 발생시키는 요청 생성
        MockHttpServletRequest problematicRequest = spy(request);
        doThrow(new IOException("Test exception")).when(problematicRequest).getReader();

        // When
        boolean result = interceptor.preHandle(problematicRequest, response, null);

        // Then
        assertFalse(result);
        assertEquals(HttpStatus.BAD_REQUEST.value(), response.getStatus());
        assertTrue(response.getContentAsString().contains("missing-jws"));
    }
}