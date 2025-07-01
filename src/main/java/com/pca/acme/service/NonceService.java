package com.pca.acme.service;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;

@Service
@RequiredArgsConstructor
public class NonceService {
    
    private static final SecureRandom secureRandom = new SecureRandom();
    private static final Base64.Encoder base64Encoder = Base64.getUrlEncoder().withoutPadding();
    
    private final NonceStore nonceStore;
    
    @Value("${acme.base-url:https://localhost:8443/acme}")
    private String baseUrl;

    /**
     * 새로운 nonce를 생성하고 저장합니다.
     * RFC 8555 §7.2에 따라 base64url 인코딩된 예측 불가능한 값을 반환합니다.
     */
    public String createNonce() {
        String nonce = generateRandomNonce();
        nonceStore.storeNonce(nonce, Instant.now());
        return nonce;
    }
    
    /**
     * Nonce가 유효한지 확인하고 사용 처리합니다.
     * @param nonce 검증할 nonce 값
     * @return 유효하면 true, 그렇지 않으면 false
     */
    public boolean validateAndConsumeNonce(String nonce) {
        return nonceStore.validateAndConsumeNonce(nonce);
    }
    
    /**
     * Nonce가 존재하는지 확인합니다 (사용하지 않고).
     * @param nonce 확인할 nonce 값
     * @return 존재하면 true, 그렇지 않으면 false
     */
    public boolean containsNonce(String nonce) {
        return nonceStore.containsNonce(nonce);
    }
    
    /**
     * 랜덤 nonce를 생성합니다.
     */
    private String generateRandomNonce() {
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
    
    /**
     * Nonce 통계 정보를 반환합니다.
     */
    public InMemoryNonceStore.NonceStats getStats() {
        if (nonceStore instanceof InMemoryNonceStore) {
            return ((InMemoryNonceStore) nonceStore).getStats();
        }
        return null;
    }
} 