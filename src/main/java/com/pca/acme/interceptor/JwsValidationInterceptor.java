package com.pca.acme.interceptor;

import java.io.IOException;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pca.acme.util.JwsValidator;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * JWS 검증을 처리하는 인터셉터
 * Directory와 NewNonce 엔드포인트는 제외하고 나머지 ACME API들에 대해서만 JWS 검증 수행
 * RFC 8555 §6.2 JWS 요구사항 구현
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JwsValidationInterceptor implements HandlerInterceptor {

    private final JwsValidator jwsValidator;
    private final ObjectMapper objectMapper;

    // JWS 검증이 필요 없는 엔드포인트들
    private static final String[] EXCLUDED_PATHS = {
        "/acme/directory",
        "/acme/new-nonce"
    };

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String requestURI = request.getRequestURI();

        // 제외된 경로인지 확인
        if (isExcludedPath(requestURI)) {
            log.debug("JWS validation skipped for excluded path: {}", requestURI);
            return true;
        }

        // ACME 경로가 아닌 경우 스킵
        if (!requestURI.startsWith("/acme/")) {
            return true;
        }

        log.debug("JWS validation required for path: {}", requestURI);

        // JWS 토큰 추출
        String jwsToken = extractJwsToken(request);
        if (jwsToken == null) {
            return sendErrorResponse(response, HttpStatus.BAD_REQUEST, "missing-jws", "JWS token is required");
        }

        // JWS 검증
        JwsValidator.JwsValidationResult validationResult = jwsValidator.validateJws(jwsToken);
        if (!validationResult.isValid()) {
            return sendErrorResponse(response, HttpStatus.BAD_REQUEST, "malformed-jws", validationResult.getErrorMessage());
        }

        // NewAccount API 특화 검증 (Nonce 검증 제외)
        if (requestURI.equals("/acme/new-account")) {
            if (!validateNewAccountJws(validationResult.getHeader(), response)) {
                return false;
            }
        }


        // 검증된 JWS 정보를 요청 속성에 저장 (컨트롤러에서 사용 가능)
        request.setAttribute("jwsHeader", validationResult.getHeader());
        request.setAttribute("jwsPayload", validationResult.getPayload());

        log.debug("JWS validation successful for path: {}", requestURI);
        return true;
    }

    /**
     * JWS 검증이 제외된 경로인지 확인
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
     * 요청에서 JWS 토큰을 추출합니다.
     * RFC 8555 §6.2에 따라 JWS는 요청 본문에 포함됩니다.
     */
    private String extractJwsToken(HttpServletRequest request) {
        try {
            // Content-Type이 application/jose+json인지 확인
            String contentType = request.getContentType();
            if (contentType == null || !contentType.contains("application/jose+json")) {
                log.warn("Invalid Content-Type for JWS request: {}", contentType);
                return null;
            }

            // 요청 본문에서 JWS 토큰 읽기
            StringBuilder sb = new StringBuilder();
            String line;
            try (var reader = request.getReader()) {
                while ((line = reader.readLine()) != null) {
                    sb.append(line);
                }
            }

            String requestBody = sb.toString().trim();
            if (requestBody.isEmpty()) {
                log.warn("Empty request body for JWS validation");
                return null;
            }

            return requestBody;

        } catch (IOException e) {
            log.error("Failed to read JWS token from request", e);
            return null;
        }
    }

    /**
     * NewAccount API JWS 헤더 검증 (Nonce 검증 제외)
     */
    private boolean validateNewAccountJws(Map<String, Object> header, HttpServletResponse response) throws IOException {
        // 1. jwk 필드 존재 확인
        if (!header.containsKey("jwk")) {
            return sendErrorResponse(response, HttpStatus.BAD_REQUEST, "malformed", "Missing 'jwk' field in JWS header for new account");
        }

        // 2. 알고리즘 검증
        String algorithm = (String) header.get("alg");
        if (!"RS256".equals(algorithm) && !"ES256".equals(algorithm)) {
            return sendErrorResponse(response, HttpStatus.BAD_REQUEST, "badSignatureAlgorithm", "Unsupported signature algorithm: " + algorithm);
        }

        // 3. url 필드 확인
        String url = (String) header.get("url");
        if (url == null || !url.endsWith("/acme/new-account")) {
            return sendErrorResponse(response, HttpStatus.BAD_REQUEST, "malformed", "Invalid or missing 'url' field in JWS header");
        }

        return true;
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

        log.warn("JWS validation failed: {} - {}", type, detail);
        return false;
    }
}