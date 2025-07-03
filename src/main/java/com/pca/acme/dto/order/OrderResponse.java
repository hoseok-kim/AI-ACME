package com.pca.acme.dto.order;

import java.time.Instant;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * ACME NewOrder API 응답 DTO
 * RFC 8555 §7.4 Order Objects 구현
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OrderResponse {

    /**
     * 주문 상태 (예: "pending", "ready", "processing", "valid", "invalid")
     */
    @JsonProperty("status")
    private String status;

    /**
     * 주문 만료 시간
     */
    @JsonProperty("expires")
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss'Z'", timezone = "UTC")
    private Instant expires;

    /**
     * 인증서에 포함될 식별자 목록
     */
    @JsonProperty("identifiers")
    private List<Identifier> identifiers;

    /**
     * 완료해야 할 인증 URL 목록
     */
    @JsonProperty("authorizations")
    private List<String> authorizations;

    /**
     * 인증서 최종 요청을 위한 URL
     */
    @JsonProperty("finalize")
    private String finalize;

    /**
     * 발급된 인증서 URL (상태가 "valid"일 때만 포함)
     */
    @JsonProperty("certificate")
    private String certificate;

    /**
     * 식별자 정보를 담는 내부 클래스
     */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
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