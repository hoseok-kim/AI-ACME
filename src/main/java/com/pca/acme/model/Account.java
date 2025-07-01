package com.pca.acme.model;

import lombok.Builder;
import lombok.Data;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * ACME 계정 모델
 * RFC 8555 §7.3 Account Objects
 */
@Data
@Builder
public class Account {
    
    /**
     * 계정 고유 ID
     */
    private String accountId;
    
    /**
     * 계정 상태
     */
    private String status;
    
    /**
     * 연락처 정보
     */
    private List<String> contact;
    
    /**
     * 공개키 (JWK 형식)
     */
    private Map<String, Object> publicKey;
    
    /**
     * 공개키 해시 (계정 식별용)
     */
    private String publicKeyHash;
    
    /**
     * 계정 생성 시간
     */
    private Instant createdAt;
    
    /**
     * 계정 수정 시간
     */
    private Instant updatedAt;
    
    /**
     * 서비스 약관 동의 여부
     */
    private Boolean termsOfServiceAgreed;
    
    /**
     * 외부 계정 바인딩
     */
    private Map<String, Object> externalAccountBinding;
} 