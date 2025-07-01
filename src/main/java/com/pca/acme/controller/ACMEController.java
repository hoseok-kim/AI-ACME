package com.pca.acme.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pca.acme.dto.account.AccountRequest;
import com.pca.acme.dto.account.AccountResponse;
import com.pca.acme.dto.directory.DirectoryResponse;
import com.pca.acme.service.AccountService;
import com.pca.acme.service.DirectoryService;
import com.pca.acme.service.NonceService;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;

@RestController
@RequiredArgsConstructor
@RequestMapping("/acme")
@CrossOrigin(origins = "*")
public class ACMEController {

    private final DirectoryService directoryService;
    private final NonceService nonceService;
    private final AccountService accountService;
    private final ObjectMapper objectMapper;

    /**
     * RFC 8555 §7.1 Directory 엔드포인트
     * ACME 클라이언트가 처음 호출해야 하는 엔드포인트
     */
    @GetMapping(
        value = "/directory",
        produces = MediaType.APPLICATION_JSON_VALUE
    )
    public DirectoryResponse directory() {
        return directoryService.getDirectory();
    }

    /**
     * RFC 8555 §7.2 NewNonce 엔드포인트
     * HEAD 메서드 (권장) - 200 OK 반환
     */
    @RequestMapping(value = "/new-nonce", method = RequestMethod.HEAD)
    public ResponseEntity<Void> newNonceHead() {
        String nonce = nonceService.createNonce();
        HttpHeaders headers = new HttpHeaders();
        headers.add("Replay-Nonce", nonce);
        headers.add("Cache-Control", "no-store");
        headers.add("Link", "<" + nonceService.getDirectoryUrl() + ">;rel=\"index\"");
        
        return ResponseEntity.ok().headers(headers).build();
    }

    /**
     * RFC 8555 §7.2 NewNonce 엔드포인트
     * GET 메서드 (선택) - 204 No Content 반환
     */
    @GetMapping("/new-nonce")
    public ResponseEntity<Void> newNonceGet() {
        String nonce = nonceService.createNonce();
        HttpHeaders headers = new HttpHeaders();
        headers.add("Replay-Nonce", nonce);
        headers.add("Cache-Control", "no-store");
        headers.add("Link", "<" + nonceService.getDirectoryUrl() + ">;rel=\"index\"");
        
        return ResponseEntity.noContent().headers(headers).build();
    }

    /**
     * RFC 8555 §7.3 NewAccount 엔드포인트
     * 새 계정 생성 또는 기존 계정 조회
     */
    @PostMapping(
        value = "/new-account",
        produces = MediaType.APPLICATION_JSON_VALUE
    )
    public ResponseEntity<AccountResponse> newAccount(HttpServletRequest request) {
        try {
            // 1. JWS 헤더에서 JWK 추출
            @SuppressWarnings("unchecked")
            Map<String, Object> jwsHeader = (Map<String, Object>) request.getAttribute("jwsHeader");
            @SuppressWarnings("unchecked")
            Map<String, Object> jwk = (Map<String, Object>) jwsHeader.get("jwk");

            // 2. JWS 페이로드에서 계정 요청 정보 추출
            String jwsPayload = (String) request.getAttribute("jwsPayload");
            AccountRequest accountRequest = objectMapper.readValue(jwsPayload, AccountRequest.class);

            // 3. 기존 계정 확인
            String publicKeyHash = accountService.generatePublicKeyHash(jwk);
            boolean isExistingAccount = accountService.getAccountByPublicKeyHash(publicKeyHash) != null;
            
            // 4. 계정 생성 또는 조회
            AccountResponse accountResponse = accountService.createOrGetAccount(accountRequest, jwk);
            
            // 5. 응답 헤더 설정
            HttpHeaders headers = new HttpHeaders();
            headers.add("Location", accountService.getAccountUrl(accountResponse.getAccountId()));
            headers.add("Replay-Nonce", nonceService.createNonce());
            
            // 6. 기존 계정이면 200 OK, 새 계정이면 201 Created
            HttpStatus status = isExistingAccount ? HttpStatus.OK : HttpStatus.CREATED;
            return ResponseEntity.status(status).headers(headers).body(accountResponse);

        } catch (IllegalArgumentException e) {
            // 비즈니스 로직 에러는 GlobalExceptionHandler에서 처리
            throw e;
        } catch (Exception e) {
            // 기타 에러
            throw new RuntimeException("Account creation failed: " + e.getMessage(), e);
        }
    }
} 