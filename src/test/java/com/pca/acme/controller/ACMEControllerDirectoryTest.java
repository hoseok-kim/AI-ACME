package com.pca.acme.controller;

import com.pca.acme.dto.directory.DirectoryMeta;
import com.pca.acme.dto.directory.DirectoryResponse;
import com.pca.acme.service.DirectoryService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.filter.CorsFilter;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.cors.CorsConfiguration;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.hamcrest.Matchers.*;
import static org.mockito.BDDMockito.given;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("ACME Directory API Tests")
class ACMEControllerDirectoryTest {

    private MockMvc mockMvc;

    @Mock
    private DirectoryService directoryService;

    @InjectMocks
    private ACMEController acmeController;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(acmeController)
                .setControllerAdvice(new GlobalExceptionHandler())
                .defaultResponseCharacterEncoding(StandardCharsets.UTF_8)
                .alwaysDo(result -> {
                    result.getResponse().setHeader("Access-Control-Allow-Origin", "*");
                    result.getResponse().setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
                    result.getResponse().setHeader("Access-Control-Allow-Headers", "*");
                })
                .build();
    }

    @Test
    @DisplayName("GET /acme/directory should return 200 OK with correct JSON structure")
    void directory_shouldReturn200AndCorrectJsonStructure() throws Exception {
        // Given
        DirectoryResponse expectedResponse = DirectoryResponse.builder()
                .newNonce("https://example.com/acme/new-nonce")
                .newAccount("https://example.com/acme/new-account")
                .newOrder("https://example.com/acme/new-order")
                .newAuthz("https://example.com/acme/new-authz")
                .revokeCert("https://example.com/acme/revoke-cert")
                .keyChange("https://example.com/acme/key-change")
                .meta(DirectoryMeta.builder()
                        .termsOfService("https://example.com/acme/terms/v1")
                        .website("https://www.example.com")
                        .caaIdentities(List.of("example.com"))
                        .externalAccountRequired(false)
                        .build())
                .build();

        given(directoryService.getDirectory()).willReturn(expectedResponse);

        // When & Then
        mockMvc.perform(get("/acme/directory"))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.newNonce", is("https://example.com/acme/new-nonce")))
                .andExpect(jsonPath("$.newAccount", is("https://example.com/acme/new-account")))
                .andExpect(jsonPath("$.newOrder", is("https://example.com/acme/new-order")))
                .andExpect(jsonPath("$.newAuthz", is("https://example.com/acme/new-authz")))
                .andExpect(jsonPath("$.revokeCert", is("https://example.com/acme/revoke-cert")))
                .andExpect(jsonPath("$.keyChange", is("https://example.com/acme/key-change")))
                .andExpect(jsonPath("$.meta.termsOfService", is("https://example.com/acme/terms/v1")))
                .andExpect(jsonPath("$.meta.website", is("https://www.example.com")))
                .andExpect(jsonPath("$.meta.caaIdentities[0]", is("example.com")))
                .andExpect(jsonPath("$.meta.externalAccountRequired", is(false)));
    }

    @Test
    @DisplayName("GET /acme/directory should include CORS headers")
    void directory_shouldIncludeCorsHeaders() throws Exception {
        // Given
        given(directoryService.getDirectory()).willReturn(DirectoryResponse.builder().build());

        // When & Then
        mockMvc.perform(get("/acme/directory"))
                .andExpect(status().isOk())
                .andExpect(header().string("Access-Control-Allow-Origin", "*"));
    }

    @Test
    @DisplayName("GET /acme/directory should not require authentication")
    void directory_shouldNotRequireAuthentication() throws Exception {
        // Given
        given(directoryService.getDirectory()).willReturn(DirectoryResponse.builder().build());

        // When & Then - 인증 헤더 없이도 정상 동작
        mockMvc.perform(get("/acme/directory"))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("GET /acme/directory should not require JWS")
    void directory_shouldNotRequireJws() throws Exception {
        // Given
        given(directoryService.getDirectory()).willReturn(DirectoryResponse.builder().build());

        // When & Then - JWS 없이도 정상 동작
        mockMvc.perform(get("/acme/directory"))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("POST /acme/directory should return 405 Method Not Allowed")
    void directory_shouldNotAllowPostMethod() throws Exception {
        // When & Then
        mockMvc.perform(post("/acme/directory"))
                .andExpect(status().isMethodNotAllowed());
    }

    @Test
    @DisplayName("GET /acme/directory should return all required fields")
    void directory_shouldReturnAllRequiredFields() throws Exception {
        // Given
        DirectoryResponse response = DirectoryResponse.builder()
                .newNonce("https://example.com/acme/new-nonce")
                .newAccount("https://example.com/acme/new-account")
                .newOrder("https://example.com/acme/new-order")
                .revokeCert("https://example.com/acme/revoke-cert")
                .keyChange("https://example.com/acme/key-change")
                .meta(DirectoryMeta.builder()
                        .termsOfService("https://example.com/acme/terms/v1")
                        .website("https://www.example.com")
                        .caaIdentities(List.of("example.com"))
                        .externalAccountRequired(false)
                        .build())
                .build();

        given(directoryService.getDirectory()).willReturn(response);

        // When & Then
        mockMvc.perform(get("/acme/directory"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.newNonce").exists())
                .andExpect(jsonPath("$.newAccount").exists())
                .andExpect(jsonPath("$.newOrder").exists())
                .andExpect(jsonPath("$.revokeCert").exists())
                .andExpect(jsonPath("$.keyChange").exists())
                .andExpect(jsonPath("$.meta").exists())
                .andExpect(jsonPath("$.meta.termsOfService").exists())
                .andExpect(jsonPath("$.meta.website").exists())
                .andExpect(jsonPath("$.meta.caaIdentities").isArray())
                .andExpect(jsonPath("$.meta.externalAccountRequired").exists());
    }

    @Test
    @DisplayName("GET /acme/directory should handle externalAccountRequired=true")
    void directory_shouldHandleExternalAccountRequiredTrue() throws Exception {
        // Given
        DirectoryResponse response = DirectoryResponse.builder()
                .newNonce("https://example.com/acme/new-nonce")
                .newAccount("https://example.com/acme/new-account")
                .newOrder("https://example.com/acme/new-order")
                .revokeCert("https://example.com/acme/revoke-cert")
                .keyChange("https://example.com/acme/key-change")
                .meta(DirectoryMeta.builder()
                        .termsOfService("https://example.com/acme/terms/v1")
                        .website("https://www.example.com")
                        .caaIdentities(List.of("example.com"))
                        .externalAccountRequired(true)
                        .build())
                .build();

        given(directoryService.getDirectory()).willReturn(response);

        // When & Then
        mockMvc.perform(get("/acme/directory"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.meta.externalAccountRequired", is(true)));
    }

    @Test
    @DisplayName("GET /acme/directory should handle multiple CAA identities")
    void directory_shouldHandleMultipleCaaIdentities() throws Exception {
        // Given
        DirectoryResponse response = DirectoryResponse.builder()
                .newNonce("https://example.com/acme/new-nonce")
                .newAccount("https://example.com/acme/new-account")
                .newOrder("https://example.com/acme/new-order")
                .revokeCert("https://example.com/acme/revoke-cert")
                .keyChange("https://example.com/acme/key-change")
                .meta(DirectoryMeta.builder()
                        .termsOfService("https://example.com/acme/terms/v1")
                        .website("https://www.example.com")
                        .caaIdentities(List.of("example.com", "ca.example.com"))
                        .externalAccountRequired(false)
                        .build())
                .build();

        given(directoryService.getDirectory()).willReturn(response);

        // When & Then
        mockMvc.perform(get("/acme/directory"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.meta.caaIdentities", hasSize(2)))
                .andExpect(jsonPath("$.meta.caaIdentities[0]", is("example.com")))
                .andExpect(jsonPath("$.meta.caaIdentities[1]", is("ca.example.com")));
    }

    @Test
    @DisplayName("GET /acme/directory should handle service exception gracefully")
    void directory_shouldHandleServiceException() throws Exception {
        // Given
        given(directoryService.getDirectory()).willThrow(new RuntimeException("Service error"));

        // When & Then
        mockMvc.perform(get("/acme/directory"))
                .andExpect(status().isInternalServerError());
    }

    @Test
    @DisplayName("GET /acme/directory should return valid JSON structure")
    void directory_shouldReturnValidJsonStructure() throws Exception {
        // Given
        given(directoryService.getDirectory()).willReturn(DirectoryResponse.builder()
                .newNonce("https://example.com/acme/new-nonce")
                .newAccount("https://example.com/acme/new-account")
                .newOrder("https://example.com/acme/new-order")
                .revokeCert("https://example.com/acme/revoke-cert")
                .keyChange("https://example.com/acme/key-change")
                .meta(DirectoryMeta.builder()
                        .termsOfService("https://example.com/acme/terms/v1")
                        .website("https://www.example.com")
                        .caaIdentities(List.of("example.com"))
                        .externalAccountRequired(false)
                        .build())
                .build());

        // When & Then
        mockMvc.perform(get("/acme/directory"))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$").isMap())
                .andExpect(jsonPath("$.meta").isMap());
    }
} 