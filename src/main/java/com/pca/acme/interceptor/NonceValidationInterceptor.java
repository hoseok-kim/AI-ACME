package com.pca.acme.interceptor;

import java.io.IOException;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pca.acme.service.NonceService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Nonce 검증을 처리하는 인터셉터
 * Directory와 NewNonce 엔드포인트는 제외하고 나머지 ACME API들에 대해서만 Nonce 검증 수행
 * RFC 8555 §6.5 Replay Protection 구현
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class NonceValidationInterceptor implements HandlerInterceptor {

    private final NonceService nonceService;
    private final ObjectMapper objectMapper;

    // Nonce 검증이 필요 없는 엔드포인트들
    private static final String[] EXCLUDED_PATHS = {
        "/acme/directory",
        "/acme/new-nonce"
    };

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String requestURI = request.getRequestURI();

        // 제외된 경로인지 확인
        if (isExcludedPath(requestURI)) {
            log.debug("Nonce validation skipped for excluded path: {}", requestURI);
            return true;
        }

        // ACME 경로가 아닌 경우 스킵
        if (!requestURI.startsWith("/acme/")) {
            return true;
        }

        log.debug("Nonce validation required for path: {}", requestURI);

        // JWS 헤더에서 nonce 추출 (이미 JwsValidationInterceptor에서 검증된 상태)
        @SuppressWarnings("unchecked")
        Map<String, Object> jwsHeader = (Map<String, Object>) request.getAttribute("jwsHeader");

        if (jwsHeader == null) {
            log.warn("JWS header not found in request attributes for path: {}", requestURI);
            return sendErrorResponse(response, HttpStatus.BAD_REQUEST, "malformed", "JWS header information is missing");
        }

        // nonce 필드 존재 확인
        String nonce = (String) jwsHeader.get("nonce");
        if (nonce == null || nonce.trim().isEmpty()) {
            log.warn("Missing nonce in JWS header for path: {}", requestURI);
            return sendErrorResponse(response, HttpStatus.BAD_REQUEST, "badNonce", "Missing 'nonce' field in JWS header");
        }

        // nonce 유효성 검증 및 소비
        if (!nonceService.validateAndConsumeNonce(nonce)) {
            log.warn("Invalid or expired nonce: {} for path: {}", nonce, requestURI);
            return sendErrorResponse(response, HttpStatus.BAD_REQUEST, "badNonce", "Invalid or expired nonce");
        }

        log.debug("Nonce validation successful for path: {} with nonce: {}", requestURI, nonce);
        return true;
    }


    /**
     * Nonce 검증이 제외된 경로인지 확인
     */
    private boolean isExcludedPath(String requestURI) {
        for (String excludedPath : EXCLUDED_PATHS) {
            if (requestURI.equals(excludedPath)) {
                return true;
            }
        }
        return false;
    }

    /**
     * ACME 에러 응답을 전송합니다.
     * RFC 8555 §6.7 Problem Details for HTTP APIs 형식 준수
     */
    private boolean sendErrorResponse(HttpServletResponse response, HttpStatus status, String type, String detail) throws IOException {
        response.setStatus(status.value());
        response.setContentType("application/problem+json;charset=UTF-8");
        response.setCharacterEncoding("UTF-8");

        Map<String, Object> errorResponse = Map.of(
            "type", "urn:ietf:params:acme:error:" + type,
            "detail", detail,
            "status", status.value()
        );

        String jsonResponse = objectMapper.writeValueAsString(errorResponse);
        response.getWriter().write(jsonResponse);
        response.getWriter().flush();

        log.warn("Nonce validation failed: {} - {}", type, detail);
        return false;
    }
}