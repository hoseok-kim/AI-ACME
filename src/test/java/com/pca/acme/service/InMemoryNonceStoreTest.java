package com.pca.acme.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Instant;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("InMemoryNonceStore Tests")
class InMemoryNonceStoreTest {

    private InMemoryNonceStore nonceStore;

    @BeforeEach
    void setUp() {
        nonceStore = new InMemoryNonceStore();
        // 테스트용 설정 값 주입
        ReflectionTestUtils.setField(nonceStore, "maxAgeSeconds", 300L);
        ReflectionTestUtils.setField(nonceStore, "maxNonceCount", 1000);
    }

    @Test
    @DisplayName("should store and validate nonce")
    void shouldStoreAndValidateNonce() {
        // Given
        String nonce = "test-nonce-123";
        Instant issuedAt = Instant.now();

        // When
        nonceStore.storeNonce(nonce, issuedAt);

        // Then
        assertTrue(nonceStore.containsNonce(nonce));
        assertTrue(nonceStore.validateAndConsumeNonce(nonce));
        assertFalse(nonceStore.containsNonce(nonce)); // 사용 후 제거됨
    }

    @Test
    @DisplayName("should reject duplicate nonce usage")
    void shouldRejectDuplicateNonceUsage() {
        // Given
        String nonce = "test-nonce-123";
        Instant issuedAt = Instant.now();
        nonceStore.storeNonce(nonce, issuedAt);

        // When & Then
        assertTrue(nonceStore.validateAndConsumeNonce(nonce)); // 첫 번째 사용은 성공
        assertFalse(nonceStore.validateAndConsumeNonce(nonce)); // 두 번째 사용은 실패
    }

    @Test
    @DisplayName("should reject non-existent nonce")
    void shouldRejectNonExistentNonce() {
        // Given
        String nonce = "non-existent-nonce";

        // When & Then
        assertFalse(nonceStore.containsNonce(nonce));
        assertFalse(nonceStore.validateAndConsumeNonce(nonce));
    }

    @Test
    @DisplayName("should reject null or empty nonce")
    void shouldRejectNullOrEmptyNonce() {
        // When & Then
        assertFalse(nonceStore.validateAndConsumeNonce(null));
        assertFalse(nonceStore.validateAndConsumeNonce(""));
        assertFalse(nonceStore.validateAndConsumeNonce("   "));
        
        assertFalse(nonceStore.containsNonce(null));
        assertFalse(nonceStore.containsNonce(""));
        assertFalse(nonceStore.containsNonce("   "));
    }

    @Test
    @DisplayName("should cleanup expired nonces")
    void shouldCleanupExpiredNonces() throws InterruptedException {
        // Given
        String nonce1 = "nonce1";
        String nonce2 = "nonce2";
        
        // 10초 전에 발급된 nonce (만료됨)
        nonceStore.storeNonce(nonce1, Instant.now().minusSeconds(10));
        // 현재 발급된 nonce (유효함)
        nonceStore.storeNonce(nonce2, Instant.now());

        // When
        nonceStore.cleanupExpiredNonces(5); // 5초 이상 된 것 정리

        // Then
        assertFalse(nonceStore.containsNonce(nonce1)); // 만료된 것 제거됨
        assertTrue(nonceStore.containsNonce(nonce2)); // 유효한 것 남아있음
    }

    @Test
    @DisplayName("should return correct nonce count")
    void shouldReturnCorrectNonceCount() {
        // Given
        assertEquals(0, nonceStore.getNonceCount());

        // When
        nonceStore.storeNonce("nonce1", Instant.now());
        nonceStore.storeNonce("nonce2", Instant.now());

        // Then
        assertEquals(2, nonceStore.getNonceCount());

        // When - 사용 후
        nonceStore.validateAndConsumeNonce("nonce1");

        // Then
        assertEquals(1, nonceStore.getNonceCount());
    }

    @Test
    @DisplayName("should handle concurrent access")
    void shouldHandleConcurrentAccess() throws InterruptedException {
        // Given
        int threadCount = 10;
        int noncesPerThread = 100;
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        CountDownLatch latch = new CountDownLatch(threadCount);

        // When
        for (int i = 0; i < threadCount; i++) {
            final int threadId = i;
            executor.submit(() -> {
                try {
                    for (int j = 0; j < noncesPerThread; j++) {
                        String nonce = "nonce-" + threadId + "-" + j;
                        nonceStore.storeNonce(nonce, Instant.now());
                        
                        // 즉시 검증
                        assertTrue(nonceStore.validateAndConsumeNonce(nonce));
                    }
                } finally {
                    latch.countDown();
                }
            });
        }

        // Then
        assertTrue(latch.await(10, TimeUnit.SECONDS));
        assertEquals(0, nonceStore.getNonceCount()); // 모든 nonce가 사용됨
        
        executor.shutdown();
    }

    @Test
    @DisplayName("should provide stats")
    void shouldProvideStats() {
        // Given
        nonceStore.storeNonce("nonce1", Instant.now());
        nonceStore.storeNonce("nonce2", Instant.now());
        nonceStore.validateAndConsumeNonce("nonce1");

        // When
        InMemoryNonceStore.NonceStats stats = nonceStore.getStats();

        // Then
        assertNotNull(stats);
        assertEquals(1, stats.getCurrentCount()); // 현재 1개 남음
        assertEquals(2, stats.getTotalIssued()); // 총 2개 발급됨
    }

    @Test
    @DisplayName("should handle max count limit")
    void shouldHandleMaxCountLimit() {
        // Given - 최대 개수를 초과하는 nonce 저장
        for (int i = 0; i < 1005; i++) {
            nonceStore.storeNonce("nonce-" + i, Instant.now());
        }

        // When
        int count = nonceStore.getNonceCount();

        // Then - 최대 개수 이하로 유지됨
        assertTrue(count <= 1000);
    }
} 