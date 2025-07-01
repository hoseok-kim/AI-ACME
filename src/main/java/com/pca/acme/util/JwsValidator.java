package com.pca.acme.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Base64;
import java.util.Map;

/**
 * JWS (JSON Web Signature) 검증을 위한 유틸리티 클래스
 * RFC 7515 JSON Web Signature (JWS) 구현
 */
@Slf4j
@Component
public class JwsValidator {

    private final ObjectMapper objectMapper;

    public JwsValidator(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    /**
     * JWS 토큰을 파싱하고 검증합니다.
     * 
     * @param jwsToken JWS 토큰 문자열
     * @return JwsValidationResult 검증 결과
     */
    public JwsValidationResult validateJws(String jwsToken) {
        try {
            // JWS 토큰은 3개의 부분으로 구성: header.payload.signature
            String[] parts = jwsToken.split("\\.");
            if (parts.length != 3) {
                return JwsValidationResult.invalid("Invalid JWS format: must have 3 parts");
            }

            String headerB64 = parts[0];
            String payloadB64 = parts[1];
            String signatureB64 = parts[2];

            // 헤더 디코딩 및 파싱
            String headerJson = new String(Base64.getUrlDecoder().decode(headerB64));
            Map<String, Object> header = objectMapper.readValue(headerJson, Map.class);

            // 페이로드 디코딩
            String payload = new String(Base64.getUrlDecoder().decode(payloadB64));

            // 기본적인 JWS 구조 검증
            if (!header.containsKey("alg")) {
                return JwsValidationResult.invalid("Missing 'alg' in JWS header");
            }

            // TODO: 실제 서명 검증 로직 구현
            // 현재는 기본 구조만 검증
            log.info("JWS validation passed for algorithm: {}", header.get("alg"));

            return JwsValidationResult.valid(header, payload);

        } catch (Exception e) {
            log.error("JWS validation failed", e);
            return JwsValidationResult.invalid("JWS validation error: " + e.getMessage());
        }
    }

    /**
     * JWS 검증 결과를 담는 클래스
     */
    public static class JwsValidationResult {
        private final boolean valid;
        private final String errorMessage;
        private final Map<String, Object> header;
        private final String payload;

        private JwsValidationResult(boolean valid, String errorMessage, Map<String, Object> header, String payload) {
            this.valid = valid;
            this.errorMessage = errorMessage;
            this.header = header;
            this.payload = payload;
        }

        public static JwsValidationResult valid(Map<String, Object> header, String payload) {
            return new JwsValidationResult(true, null, header, payload);
        }

        public static JwsValidationResult invalid(String errorMessage) {
            return new JwsValidationResult(false, errorMessage, null, null);
        }

        public boolean isValid() {
            return valid;
        }

        public String getErrorMessage() {
            return errorMessage;
        }

        public Map<String, Object> getHeader() {
            return header;
        }

        public String getPayload() {
            return payload;
        }
    }
} 