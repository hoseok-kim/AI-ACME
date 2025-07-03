package com.pca.acme.model;

import java.time.Instant;
import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * ACME Authorization 모델 클래스
 * RFC 8555 §7.5 Authorization Objects 구현
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Authorization {

    /**
     * 인증 고유 ID
     */
    private String authorizationId;

    /**
     * 인증할 식별자
     */
    private Identifier identifier;

    /**
     * 인증 상태
     * pending, valid, invalid, deactivated, expired, revoked
     */
    private AuthorizationStatus status;

    /**
     * 인증 만료 시간 (선택사항)
     */
    private Instant expires;

    /**
     * 클라이언트가 수행해야 하는 챌린지 목록
     */
    private List<Challenge> challenges;

    /**
     * 와일드카드 도메인 여부 (선택사항)
     */
    private Boolean wildcard;

    /**
     * 인증 상태 열거형
     */
    public enum AuthorizationStatus {
        PENDING("pending"),
        VALID("valid"),
        INVALID("invalid"),
        DEACTIVATED("deactivated"),
        EXPIRED("expired"),
        REVOKED("revoked");

        private final String value;

        AuthorizationStatus(String value) {
            this.value = value;
        }

        public String getValue() {
            return value;
        }
    }

    /**
     * 챌린지 정보를 담는 내부 클래스
     */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Challenge {
        /**
         * 챌린지 타입 (예: "http-01", "dns-01")
         */
        private String type;

        /**
         * 챌린지 URL
         */
        private String url;

        /**
         * 챌린지 토큰
         */
        private String token;

        /**
         * 챌린지 상태
         */
        private String status;

        /**
         * 검증된 시간
         */
        private Instant validated;

        /**
         * 에러 정보
         */
        private Object error;
    }
}