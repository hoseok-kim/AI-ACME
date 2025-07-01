package com.pca.acme.dto.account;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.Data;

import java.util.List;

/**
 * ACME NewAccount API 응답 DTO
 * RFC 8555 §7.3 Account Objects
 */
@Data
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AccountResponse {
    
    /**
     * 계정 상태
     * valid, deactivated, revoked
     */
    private String status;
    
    /**
     * 연락처 정보
     */
    @JsonInclude(JsonInclude.Include.ALWAYS)
    private List<String> contact;
    
    /**
     * 계정의 주문 목록 URL
     */
    private String orders;
    
    /**
     * 계정 ID (내부적으로 사용)
     */
    private String accountId;
} 