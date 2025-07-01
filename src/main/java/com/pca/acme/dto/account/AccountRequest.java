package com.pca.acme.dto.account;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.util.List;
import java.util.Map;

/**
 * ACME NewAccount API 요청 DTO
 * RFC 8555 §7.3 Account Objects
 */
@Data
public class AccountRequest {
    
    /**
     * 연락처 정보 (선택사항)
     * mailto: 또는 tel: URI 형식
     */
    private List<String> contact;
    
    /**
     * 서비스 약관 동의 여부 (필수)
     */
    @JsonProperty("termsOfServiceAgreed")
    private Boolean termsOfServiceAgreed;
    
    /**
     * 외부 계정 바인딩 (선택사항)
     * RFC 8555 §7.3.4 External Account Binding
     */
    @JsonProperty("externalAccountBinding")
    private Map<String, Object> externalAccountBinding;
} 