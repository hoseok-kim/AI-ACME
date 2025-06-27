package com.pca.acme.controller;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import com.pca.acme.dto.directory.DirectoryMeta;
import com.pca.acme.dto.directory.DirectoryResponse;
import com.pca.acme.service.DirectoryService;

import static org.hamcrest.Matchers.notNullValue;
import static org.mockito.BDDMockito.given;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@ExtendWith(MockitoExtension.class)
public class ACMEControllerTest {
    
    private MockMvc mockMvc;
    
    @Mock
    private DirectoryService directoryService;
    
    @InjectMocks
    private ACMEController acmeController;
    
    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(acmeController).build();
    }
    
    @Test
    void directory_shouldReturnJson() throws Exception {
        /** ② 목 객체가 반환할 더미 응답 정의 */
        DirectoryResponse dummy = DirectoryResponse.builder()
            .newNonce("https://example.com/acme/new-nonce")
            .newAccount("https://example.com/acme/new-account")
            .newOrder("https://example.com/acme/new-order")
            .revokeCert("https://example.com/acme/revoke-cert")
            .keyChange("https://example.com/acme/key-change")
            .meta(DirectoryMeta.builder()
                .termsOfService("https://example.com/tos")
                .externalAccountRequired(false)
                .build())
            .build();

        given(directoryService.getDirectory()).willReturn(dummy);

        /** ③ 실제 호출 & 검증 */
        mockMvc.perform(get("/acme/directory"))
            .andExpect(status().isOk())
            .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
            .andExpect(jsonPath("$.newNonce", notNullValue()))
            .andExpect(jsonPath("$.meta").exists());
    }
}
