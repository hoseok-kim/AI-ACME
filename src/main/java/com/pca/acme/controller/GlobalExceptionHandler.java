package com.pca.acme.controller;

import java.util.Map;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import com.pca.acme.service.NonceService;

import lombok.RequiredArgsConstructor;

@RestControllerAdvice
@RequiredArgsConstructor
public class GlobalExceptionHandler {

    private final NonceService nonceService;

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<String> handleMethodNotAllowed(HttpRequestMethodNotSupportedException ex) {
        return ResponseEntity.status(405).body("Method Not Allowed");
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, Object>> handleIllegalArgument(IllegalArgumentException ex) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Replay-Nonce", nonceService.createNonce());
        headers.add("Content-Type", "application/problem+json;charset=UTF-8");

        String message = ex.getMessage();
        String errorType = "malformed";

        // 에러 메시지에 따라 적절한 ACME 에러 타입 결정
        if (message.contains("Terms of service")) {
            errorType = "userActionRequired";
        } else if (message.contains("Invalid contact")) {
            errorType = "invalidContact";
        }

        Map<String, Object> errorResponse = Map.of(
            "type", "urn:ietf:params:acme:error:" + errorType,
            "detail", message,
            "status", 400
        );

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).headers(headers).body(errorResponse);
    }

    /**
     * UnsupportedOperationException 처리 (지원하지 않는 식별자 타입 등)
     */
    @ExceptionHandler(UnsupportedOperationException.class)
    public ResponseEntity<Map<String, Object>> handleUnsupportedOperation(UnsupportedOperationException ex) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Replay-Nonce", nonceService.createNonce());
        headers.add("Content-Type", "application/problem+json;charset=UTF-8");

        Map<String, Object> errorResponse = Map.of(
            "type", "urn:ietf:params:acme:error:unsupportedIdentifier",
            "detail", ex.getMessage(),
            "status", 400
        );

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).headers(headers).body(errorResponse);
    }

    /**
     * RuntimeException 처리 (계정 없음 등)
     */
    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<Map<String, Object>> handleRuntimeException(RuntimeException ex) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Replay-Nonce", nonceService.createNonce());
        headers.add("Content-Type", "application/problem+json;charset=UTF-8");

        String message = ex.getMessage();
        String errorType = "serverInternal";
        HttpStatus status = HttpStatus.INTERNAL_SERVER_ERROR;

        // 계정 없음 에러 처리
        if (message != null && message.contains("Account not found")) {
            errorType = "accountDoesNotExist";
            status = HttpStatus.NOT_FOUND;
        }

        Map<String, Object> errorResponse = Map.of(
            "type", "urn:ietf:params:acme:error:" + errorType,
            "detail", message,
            "status", status.value()
        );

        return ResponseEntity.status(status).headers(headers).body(errorResponse);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<String> handleException(Exception ex) {
        return ResponseEntity.status(500).body("Internal Server Error");
    }
}