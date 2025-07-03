package com.pca.acme.model;

import java.time.Instant;
import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * ACME Order 모델 클래스
 * RFC 8555 §7.4 Order Objects 구현
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Order {

    /**
     * 주문 고유 ID
     */
    private String orderId;

    /**
     * 주문을 생성한 계정 ID
     */
    private String accountId;

    /**
     * 주문 상태
     * pending, ready, processing, valid, invalid
     */
    private OrderStatus status;

    /**
     * 주문 생성 시간
     */
    private Instant createdAt;

    /**
     * 주문 만료 시간
     */
    private Instant expiresAt;

    /**
     * 마지막 업데이트 시간
     */
    private Instant updatedAt;

    /**
     * 인증서에 포함될 식별자 목록
     */
    private List<Identifier> identifiers;

    /**
     * 인증 URL 목록
     */
    private List<String> authorizations;

    /**
     * 최종 요청 URL
     */
    private String finalizeUrl;

    /**
     * 발급된 인증서 URL (상태가 valid일 때만)
     */
    private String certificateUrl;

    /**
     * 주문 상태 열거형
     */
    public enum OrderStatus {
        PENDING("pending"),
        READY("ready"),
        PROCESSING("processing"),
        VALID("valid"),
        INVALID("invalid");

        private final String value;

        OrderStatus(String value) {
            this.value = value;
        }

        public String getValue() {
            return value;
        }
    }

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
        private String type;

        /**
         * 식별자 값 (예: "example.com")
         */
        private String value;
    }
}