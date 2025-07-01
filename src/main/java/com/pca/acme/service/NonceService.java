package com.pca.acme.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.Base64;

@Service
public class NonceService {
    
    private static final SecureRandom secureRandom = new SecureRandom();
    private static final Base64.Encoder base64Encoder = Base64.getUrlEncoder().withoutPadding();
    
    @Value("${acme.base-url:https://localhost:8443/acme}")
    private String baseUrl;

    /**
     * 새로운 nonce를 생성합니다.
     * RFC 8555 §7.2에 따라 base64url 인코딩된 예측 불가능한 값을 반환합니다.
     */
    public String createNonce() {
        byte[] randomBytes = new byte[16];
        secureRandom.nextBytes(randomBytes);
        return base64Encoder.encodeToString(randomBytes);
    }
    
    /**
     * Directory URL을 반환합니다.
     */
    public String getDirectoryUrl() {
        return baseUrl + "/directory";
    }
} 