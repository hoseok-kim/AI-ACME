package com.pca.acme.controller;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.HttpRequestMethodNotSupportedException;

import com.pca.acme.service.NonceService;
import lombok.RequiredArgsConstructor;

import java.util.Map;

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

    @ExceptionHandler(Exception.class)
    public ResponseEntity<String> handleException(Exception ex) {
        return ResponseEntity.status(500).body("Internal Server Error");
    }
} 