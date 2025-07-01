package com.pca.acme.service;

import com.pca.acme.dto.account.AccountRequest;
import com.pca.acme.dto.account.AccountResponse;
import com.pca.acme.model.Account;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Pattern;

/**
 * ACME 계정 관리 서비스
 * RFC 8555 §7.3 Account Management 구현
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AccountService {

    @Value("${acme.base-url:https://localhost:8443}")
    private String baseUrl;

    // 메모리 기반 계정 저장소 (실제 환경에서는 데이터베이스 사용)
    private final Map<String, Account> accountsByHash = new ConcurrentHashMap<>();
    private final Map<String, Account> accountsById = new ConcurrentHashMap<>();
    private final AtomicLong accountIdCounter = new AtomicLong(1);

    // 연락처 유효성 검증을 위한 패턴
    private static final Pattern EMAIL_PATTERN = Pattern.compile("^mailto:[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$");
    private static final Pattern TEL_PATTERN = Pattern.compile("^tel:\\+?[1-9]\\d{1,14}$");

    /**
     * 새 계정 생성 또는 기존 계정 조회
     */
    public AccountResponse createOrGetAccount(AccountRequest request, Map<String, Object> jwk) {
        // 1. 요청 유효성 검증
        validateAccountRequest(request);
        
        // 2. 연락처 형식 검증
        validateContactFormats(request.getContact());
        
        // 3. 공개키 해시 생성
        String publicKeyHash = generatePublicKeyHash(jwk);
        
        // 4. 기존 계정 확인
        Account existingAccount = accountsByHash.get(publicKeyHash);
        if (existingAccount != null) {
            log.info("Returning existing account: {}", existingAccount.getAccountId());
            return buildAccountResponse(existingAccount, false);
        }
        
        // 5. 새 계정 생성
        Account newAccount = createNewAccount(request, jwk, publicKeyHash);
        
        // 6. 계정 저장
        accountsByHash.put(publicKeyHash, newAccount);
        accountsById.put(newAccount.getAccountId(), newAccount);
        
        log.info("Created new account: {}", newAccount.getAccountId());
        return buildAccountResponse(newAccount, true);
    }

    /**
     * 계정 ID로 계정 조회
     */
    public Account getAccountById(String accountId) {
        return accountsById.get(accountId);
    }

    /**
     * 공개키 해시로 계정 조회
     */
    public Account getAccountByPublicKeyHash(String publicKeyHash) {
        return accountsByHash.get(publicKeyHash);
    }

    /**
     * 계정 요청 유효성 검증
     */
    private void validateAccountRequest(AccountRequest request) {
        if (request.getTermsOfServiceAgreed() == null) {
            throw new IllegalArgumentException("termsOfServiceAgreed field is required");
        }
        if (!request.getTermsOfServiceAgreed()) {
            throw new IllegalArgumentException("Terms of service agreement is required");
        }
    }

    /**
     * 연락처 형식 유효성 검증
     */
    private void validateContactFormats(List<String> contacts) {
        if (contacts == null || contacts.isEmpty()) {
            return; // 연락처는 선택사항
        }

        for (String contact : contacts) {
            if (!EMAIL_PATTERN.matcher(contact).matches() && 
                !TEL_PATTERN.matcher(contact).matches()) {
                throw new IllegalArgumentException("Invalid contact format: " + contact);
            }
        }
    }

    /**
     * 공개키 해시 생성
     */
    public String generatePublicKeyHash(Map<String, Object> jwk) {
        try {
            // JWK를 정규화된 JSON 문자열로 변환
            String jwkString = normalizeJwk(jwk);
            
            // SHA-256 해시 생성
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(jwkString.getBytes());
            
            // Base64 URL 인코딩
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }

    /**
     * JWK 정규화 (일관된 해시를 위해)
     */
    private String normalizeJwk(Map<String, Object> jwk) {
        // 필수 필드만 추출하여 정렬된 형태로 생성
        Map<String, Object> normalized = new TreeMap<>();
        normalized.put("kty", jwk.get("kty"));
        normalized.put("n", jwk.get("n"));
        normalized.put("e", jwk.get("e"));
        
        return normalized.toString();
    }

    /**
     * 새 계정 생성
     */
    private Account createNewAccount(AccountRequest request, Map<String, Object> jwk, String publicKeyHash) {
        String accountId = String.valueOf(accountIdCounter.getAndIncrement());
        Instant now = Instant.now();
        
        return Account.builder()
                .accountId(accountId)
                .status("valid")
                .contact(request.getContact())
                .publicKey(jwk)
                .publicKeyHash(publicKeyHash)
                .createdAt(now)
                .updatedAt(now)
                .termsOfServiceAgreed(request.getTermsOfServiceAgreed())
                .externalAccountBinding(request.getExternalAccountBinding())
                .build();
    }

    /**
     * 계정 응답 생성
     */
    private AccountResponse buildAccountResponse(Account account, boolean isNewAccount) {
        return AccountResponse.builder()
                .status(account.getStatus())
                .contact(account.getContact())
                .orders(baseUrl + "/acme/acct/" + account.getAccountId() + "/orders")
                .accountId(account.getAccountId())
                .build();
    }

    /**
     * 계정 URL 생성
     */
    public String getAccountUrl(String accountId) {
        return baseUrl + "/acme/acct/" + accountId;
    }
} 