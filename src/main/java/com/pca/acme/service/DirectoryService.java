package com.pca.acme.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.pca.acme.dto.directory.DirectoryMeta;
import com.pca.acme.dto.directory.DirectoryResponse;

import java.util.List;

@Service
public class DirectoryService {

    @Value("${acme.base-url:https://localhost:8443/acme}")
    private String baseUrl;

    public DirectoryResponse getDirectory() {
        String prefix = baseUrl.endsWith("/") ? baseUrl : baseUrl + "/";

        return DirectoryResponse.builder()
            .newNonce(prefix + "new-nonce")
            .newAccount(prefix + "new-account")
            .newOrder(prefix + "new-order")
            .newAuthz(prefix + "new-authz")
            .revokeCert(prefix + "revoke-cert")
            .keyChange(prefix + "key-change")
            .meta(DirectoryMeta.builder()
                .termsOfService("https://example.com/acme/terms/v1")
                .website("https://www.example.com")
                .caaIdentities(List.of("example.com"))
                .externalAccountRequired(false)
                .build())
            .build();
    }
} 