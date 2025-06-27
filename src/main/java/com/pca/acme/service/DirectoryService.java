package com.pca.acme.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.pca.acme.dto.directory.DirectoryMeta;
import com.pca.acme.dto.directory.DirectoryResponse;

@Service
public class DirectoryService {

    @Value("${acme.base-url}")          // e.g. https://ca.example.com/acme
    private String baseUrl;

    /**
     * DirectoryResponse를 빌드해 반환
     */
    public DirectoryResponse getDirectory() {
        String prefix = baseUrl.endsWith("/") ? baseUrl : baseUrl + "/";

        return DirectoryResponse.builder()
            .newNonce(prefix + "new-nonce")
            .newAccount(prefix + "new-account")
            .newOrder(prefix + "new-order")
            .revokeCert(prefix + "revoke-cert")
            .keyChange(prefix + "key-change")
            .meta(DirectoryMeta.builder()
                .termsOfService("https://ca.example.com/tos.html")
                .website("https://ca.example.com")
                .caaIdentities(java.util.List.of("ca.example.com"))
                .externalAccountRequired(false)          // EAB 사용 시 true
                .build())
            .build();
    }
}
