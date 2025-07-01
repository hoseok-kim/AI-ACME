package com.pca.acme.service;

import java.time.Instant;

/**
 * ACME Nonce 관리를 위한 인터페이스
 * RFC 8555 §7.2에 따라 Nonce 재사용을 방지합니다.
 */
public interface NonceStore {
    
    /**
     * 새로운 Nonce를 저장합니다.
     * @param nonce 저장할 nonce 값
     * @param issuedAt 발급 시간
     */
    void storeNonce(String nonce, Instant issuedAt);
    
    /**
     * Nonce가 유효한지 확인하고 사용 처리합니다.
     * @param nonce 검증할 nonce 값
     * @return 유효하면 true, 그렇지 않으면 false
     */
    boolean validateAndConsumeNonce(String nonce);
    
    /**
     * Nonce가 존재하는지 확인합니다 (사용하지 않고).
     * @param nonce 확인할 nonce 값
     * @return 존재하면 true, 그렇지 않으면 false
     */
    boolean containsNonce(String nonce);
    
    /**
     * 만료된 Nonce들을 정리합니다.
     * @param maxAge 최대 유효 시간 (초)
     */
    void cleanupExpiredNonces(long maxAge);
    
    /**
     * 저장된 Nonce 개수를 반환합니다.
     * @return Nonce 개수
     */
    int getNonceCount();
} 