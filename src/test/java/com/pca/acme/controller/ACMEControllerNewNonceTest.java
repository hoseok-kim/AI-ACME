package com.pca.acme.controller;

import com.pca.acme.service.NonceService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.nio.charset.StandardCharsets;

import static org.hamcrest.Matchers.*;
import static org.mockito.BDDMockito.given;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.head;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("ACME NewNonce API Tests")
class ACMEControllerNewNonceTest {

    private MockMvc mockMvc;

    @Mock
    private NonceService nonceService;

    @InjectMocks
    private ACMEController acmeController;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(acmeController)
                .setControllerAdvice(new GlobalExceptionHandler(nonceService))
                .defaultResponseCharacterEncoding(StandardCharsets.UTF_8)
                .alwaysDo(result -> {
                    result.getResponse().setHeader("Access-Control-Allow-Origin", "*");
                    result.getResponse().setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, HEAD");
                    result.getResponse().setHeader("Access-Control-Allow-Headers", "*");
                })
                .build();
    }

    @Test
    @DisplayName("HEAD /acme/new-nonce should return 200 OK with required headers")
    void newNonceHead_shouldReturn200WithRequiredHeaders() throws Exception {
        // Given
        String expectedNonce = "oFvnlFP1wIhRlYS2jTaXbA";
        String expectedDirectoryUrl = "https://localhost:8443/acme/directory";
        
        given(nonceService.createNonce()).willReturn(expectedNonce);
        given(nonceService.getDirectoryUrl()).willReturn(expectedDirectoryUrl);

        // When & Then
        mockMvc.perform(head("/acme/new-nonce"))
                .andExpect(status().isOk())
                .andExpect(header().string("Replay-Nonce", expectedNonce))
                .andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(header().string("Link", "<" + expectedDirectoryUrl + ">;rel=\"index\""))
                .andExpect(content().string("")); // 응답 바디는 비어있어야 함
    }

    @Test
    @DisplayName("GET /acme/new-nonce should return 204 No Content with required headers")
    void newNonceGet_shouldReturn204WithRequiredHeaders() throws Exception {
        // Given
        String expectedNonce = "oFvnlFP1wIhRlYS2jTaXbA";
        String expectedDirectoryUrl = "https://localhost:8443/acme/directory";
        
        given(nonceService.createNonce()).willReturn(expectedNonce);
        given(nonceService.getDirectoryUrl()).willReturn(expectedDirectoryUrl);

        // When & Then
        mockMvc.perform(get("/acme/new-nonce"))
                .andExpect(status().isNoContent())
                .andExpect(header().string("Replay-Nonce", expectedNonce))
                .andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(header().string("Link", "<" + expectedDirectoryUrl + ">;rel=\"index\""))
                .andExpect(content().string("")); // 응답 바디는 비어있어야 함
    }

    @Test
    @DisplayName("HEAD /acme/new-nonce should not require authentication")
    void newNonceHead_shouldNotRequireAuthentication() throws Exception {
        // Given
        given(nonceService.createNonce()).willReturn("test-nonce");
        given(nonceService.getDirectoryUrl()).willReturn("https://localhost:8443/acme/directory");

        // When & Then - 인증 헤더 없이도 정상 동작
        mockMvc.perform(head("/acme/new-nonce"))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("GET /acme/new-nonce should not require authentication")
    void newNonceGet_shouldNotRequireAuthentication() throws Exception {
        // Given
        given(nonceService.createNonce()).willReturn("test-nonce");
        given(nonceService.getDirectoryUrl()).willReturn("https://localhost:8443/acme/directory");

        // When & Then - 인증 헤더 없이도 정상 동작
        mockMvc.perform(get("/acme/new-nonce"))
                .andExpect(status().isNoContent());
    }

    @Test
    @DisplayName("POST /acme/new-nonce should return 405 Method Not Allowed")
    void newNonce_shouldNotAllowPostMethod() throws Exception {
        // When & Then
        mockMvc.perform(post("/acme/new-nonce"))
                .andExpect(status().isMethodNotAllowed());
    }

    @Test
    @DisplayName("HEAD /acme/new-nonce should return unique nonce each time")
    void newNonceHead_shouldReturnUniqueNonceEachTime() throws Exception {
        // Given
        given(nonceService.createNonce())
                .willReturn("nonce1")
                .willReturn("nonce2");
        given(nonceService.getDirectoryUrl()).willReturn("https://localhost:8443/acme/directory");

        // When & Then
        mockMvc.perform(head("/acme/new-nonce"))
                .andExpect(status().isOk())
                .andExpect(header().string("Replay-Nonce", "nonce1"));

        mockMvc.perform(head("/acme/new-nonce"))
                .andExpect(status().isOk())
                .andExpect(header().string("Replay-Nonce", "nonce2"));
    }

    @Test
    @DisplayName("GET /acme/new-nonce should return unique nonce each time")
    void newNonceGet_shouldReturnUniqueNonceEachTime() throws Exception {
        // Given
        given(nonceService.createNonce())
                .willReturn("nonce1")
                .willReturn("nonce2");
        given(nonceService.getDirectoryUrl()).willReturn("https://localhost:8443/acme/directory");

        // When & Then
        mockMvc.perform(get("/acme/new-nonce"))
                .andExpect(status().isNoContent())
                .andExpect(header().string("Replay-Nonce", "nonce1"));

        mockMvc.perform(get("/acme/new-nonce"))
                .andExpect(status().isNoContent())
                .andExpect(header().string("Replay-Nonce", "nonce2"));
    }

    @Test
    @DisplayName("HEAD /acme/new-nonce should return base64url encoded nonce")
    void newNonceHead_shouldReturnBase64UrlEncodedNonce() throws Exception {
        // Given
        String expectedNonce = "oFvnlFP1wIhRlYS2jTaXbA"; // base64url encoded
        given(nonceService.createNonce()).willReturn(expectedNonce);
        given(nonceService.getDirectoryUrl()).willReturn("https://localhost:8443/acme/directory");

        // When & Then
        mockMvc.perform(head("/acme/new-nonce"))
                .andExpect(status().isOk())
                .andExpect(header().string("Replay-Nonce", matchesPattern("^[A-Za-z0-9_-]+$"))); // base64url pattern
    }

    @Test
    @DisplayName("GET /acme/new-nonce should return base64url encoded nonce")
    void newNonceGet_shouldReturnBase64UrlEncodedNonce() throws Exception {
        // Given
        String expectedNonce = "oFvnlFP1wIhRlYS2jTaXbA"; // base64url encoded
        given(nonceService.createNonce()).willReturn(expectedNonce);
        given(nonceService.getDirectoryUrl()).willReturn("https://localhost:8443/acme/directory");

        // When & Then
        mockMvc.perform(get("/acme/new-nonce"))
                .andExpect(status().isNoContent())
                .andExpect(header().string("Replay-Nonce", matchesPattern("^[A-Za-z0-9_-]+$"))); // base64url pattern
    }

    @Test
    @DisplayName("HEAD /acme/new-nonce should include CORS headers")
    void newNonceHead_shouldIncludeCorsHeaders() throws Exception {
        // Given
        given(nonceService.createNonce()).willReturn("test-nonce");
        given(nonceService.getDirectoryUrl()).willReturn("https://localhost:8443/acme/directory");

        // When & Then
        mockMvc.perform(head("/acme/new-nonce"))
                .andExpect(status().isOk())
                .andExpect(header().string("Access-Control-Allow-Origin", "*"));
    }

    @Test
    @DisplayName("GET /acme/new-nonce should include CORS headers")
    void newNonceGet_shouldIncludeCorsHeaders() throws Exception {
        // Given
        given(nonceService.createNonce()).willReturn("test-nonce");
        given(nonceService.getDirectoryUrl()).willReturn("https://localhost:8443/acme/directory");

        // When & Then
        mockMvc.perform(get("/acme/new-nonce"))
                .andExpect(status().isNoContent())
                .andExpect(header().string("Access-Control-Allow-Origin", "*"));
    }

    @Test
    @DisplayName("HEAD /acme/new-nonce should handle service exception gracefully")
    void newNonceHead_shouldHandleServiceException() throws Exception {
        // Given
        given(nonceService.createNonce()).willThrow(new RuntimeException("Service error"));

        // When & Then
        mockMvc.perform(head("/acme/new-nonce"))
                .andExpect(status().isInternalServerError());
    }

    @Test
    @DisplayName("GET /acme/new-nonce should handle service exception gracefully")
    void newNonceGet_shouldHandleServiceException() throws Exception {
        // Given
        given(nonceService.createNonce()).willThrow(new RuntimeException("Service error"));

        // When & Then
        mockMvc.perform(get("/acme/new-nonce"))
                .andExpect(status().isInternalServerError());
    }

    @Test
    @DisplayName("HEAD /acme/new-nonce should return empty response body")
    void newNonceHead_shouldReturnEmptyResponseBody() throws Exception {
        // Given
        given(nonceService.createNonce()).willReturn("test-nonce");
        given(nonceService.getDirectoryUrl()).willReturn("https://localhost:8443/acme/directory");

        // When & Then
        mockMvc.perform(head("/acme/new-nonce"))
                .andExpect(status().isOk())
                .andExpect(content().string(""));
    }

    @Test
    @DisplayName("GET /acme/new-nonce should return empty response body")
    void newNonceGet_shouldReturnEmptyResponseBody() throws Exception {
        // Given
        given(nonceService.createNonce()).willReturn("test-nonce");
        given(nonceService.getDirectoryUrl()).willReturn("https://localhost:8443/acme/directory");

        // When & Then
        mockMvc.perform(get("/acme/new-nonce"))
                .andExpect(status().isNoContent())
                .andExpect(content().string(""));
    }
} 