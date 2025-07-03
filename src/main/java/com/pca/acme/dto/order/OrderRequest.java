package com.pca.acme.dto.order;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Data;

/**
 * ACME NewOrder API 요청 DTO
 * RFC 8555 §7.4 Order Objects 구현
 */
@Data
public class OrderRequest {

    /**
     * 인증서에 포함될 식별자 목록
     * 각 식별자는 type과 value를 포함해야 함
     */
    @JsonProperty("identifiers")
    private List<Identifier> identifiers;

    /**
     * 식별자 정보를 담는 내부 클래스
     */
    @Data
    public static class Identifier {
        /**
         * 식별자 타입 (예: "dns")
         */
        @JsonProperty("type")
        private String type;

        /**
         * 식별자 값 (예: "example.com")
         */
        @JsonProperty("value")
        private String value;
    }
}