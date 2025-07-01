package com.pca.acme.util;

import com.pca.acme.service.NonceService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/**
 * Nonce 검증을 위한 유틸리티 클래스
 * ACME 요청에서 Nonce를 검증하는 데 사용됩니다.
 */
@Component
@RequiredArgsConstructor
public class NonceValidator {
    
    private final NonceService nonceService;
    
    /**
     * Nonce를 검증하고 사용 처리합니다.
     * @param nonce 검증할 nonce 값
     * @return 유효하면 true, 그렇지 않으면 false
     */
    public boolean validateNonce(String nonce) {
        if (nonce == null || nonce.trim().isEmpty()) {
            return false;
        }
        
        return nonceService.validateAndConsumeNonce(nonce);
    }
    
    /**
     * Nonce가 존재하는지 확인합니다 (사용하지 않고).
     * @param nonce 확인할 nonce 값
     * @return 존재하면 true, 그렇지 않으면 false
     */
    public boolean hasNonce(String nonce) {
        if (nonce == null || nonce.trim().isEmpty()) {
            return false;
        }
        
        return nonceService.containsNonce(nonce);
    }
    
    /**
     * Nonce가 유효한 형식인지 확인합니다.
     * @param nonce 확인할 nonce 값
     * @return 유효한 형식이면 true, 그렇지 않으면 false
     */
    public boolean isValidFormat(String nonce) {
        if (nonce == null || nonce.trim().isEmpty()) {
            return false;
        }
        
        // base64url 인코딩 패턴 확인
        return nonce.matches("^[A-Za-z0-9_-]+$");
    }
} 