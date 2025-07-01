package com.pca.acme.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 메모리 기반 Nonce Store 구현체
 * 프로덕션에서는 Redis나 데이터베이스를 사용하는 것을 권장합니다.
 */
@Service
public class InMemoryNonceStore implements NonceStore {
    
    private final Map<String, Instant> nonces = new ConcurrentHashMap<>();
    private final AtomicInteger nonceCounter = new AtomicInteger(0);
    
    @Value("${acme.nonce.max-age:300}") // 기본 5분
    private long maxAgeSeconds;
    
    @Value("${acme.nonce.max-count:1000}") // 기본 최대 1000개
    private int maxNonceCount;
    
    @Override
    public void storeNonce(String nonce, Instant issuedAt) {
        // 최대 개수 제한 확인
        if (nonces.size() >= maxNonceCount) {
            cleanupExpiredNonces(maxAgeSeconds);
            // 여전히 최대 개수에 도달했다면 가장 오래된 것 제거
            if (nonces.size() >= maxNonceCount) {
                removeOldestNonce();
            }
        }
        
        nonces.put(nonce, issuedAt);
        nonceCounter.incrementAndGet();
    }
    
    @Override
    public boolean validateAndConsumeNonce(String nonce) {
        if (nonce == null || nonce.trim().isEmpty()) {
            return false;
        }
        
        Instant issuedAt = nonces.remove(nonce);
        if (issuedAt == null) {
            return false; // Nonce가 존재하지 않음
        }
        
        // 만료 시간 확인
        Instant now = Instant.now();
        if (issuedAt.plusSeconds(maxAgeSeconds).isBefore(now)) {
            return false; // Nonce가 만료됨
        }
        
        return true;
    }
    
    @Override
    public boolean containsNonce(String nonce) {
        if (nonce == null || nonce.trim().isEmpty()) {
            return false;
        }
        
        Instant issuedAt = nonces.get(nonce);
        if (issuedAt == null) {
            return false;
        }
        
        // 만료 시간 확인
        Instant now = Instant.now();
        return !issuedAt.plusSeconds(maxAgeSeconds).isBefore(now);
    }
    
    @Override
    public void cleanupExpiredNonces(long maxAge) {
        Instant cutoff = Instant.now().minusSeconds(maxAge);
        nonces.entrySet().removeIf(entry -> entry.getValue().isBefore(cutoff));
    }
    
    @Override
    public int getNonceCount() {
        return nonces.size();
    }
    
    /**
     * 가장 오래된 Nonce를 제거합니다.
     */
    private void removeOldestNonce() {
        nonces.entrySet().stream()
                .min(Map.Entry.comparingByValue())
                .ifPresent(entry -> nonces.remove(entry.getKey()));
    }
    
    /**
     * 정기적으로 만료된 Nonce를 정리합니다 (5분마다).
     */
    @Scheduled(fixedRate = 300000) // 5분
    public void scheduledCleanup() {
        cleanupExpiredNonces(maxAgeSeconds);
    }
    
    /**
     * 통계 정보를 반환합니다.
     */
    public NonceStats getStats() {
        return new NonceStats(
                nonces.size(),
                nonceCounter.get(),
                maxNonceCount,
                maxAgeSeconds
        );
    }
    
    /**
     * Nonce 통계 정보
     */
    public static class NonceStats {
        private final int currentCount;
        private final int totalIssued;
        private final int maxCount;
        private final long maxAgeSeconds;
        
        public NonceStats(int currentCount, int totalIssued, int maxCount, long maxAgeSeconds) {
            this.currentCount = currentCount;
            this.totalIssued = totalIssued;
            this.maxCount = maxCount;
            this.maxAgeSeconds = maxAgeSeconds;
        }
        
        public int getCurrentCount() { return currentCount; }
        public int getTotalIssued() { return totalIssued; }
        public int getMaxCount() { return maxCount; }
        public long getMaxAgeSeconds() { return maxAgeSeconds; }
    }
} 