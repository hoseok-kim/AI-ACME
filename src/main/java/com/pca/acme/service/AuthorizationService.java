package com.pca.acme.service;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.pca.acme.model.Authorization;
import com.pca.acme.model.Identifier;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * ACME Authorization 관리 서비스
 * RFC 8555 §7.5 Authorization Objects 구현
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuthorizationService {

    private final Map<String, Authorization> authorizations = new ConcurrentHashMap<>();

    @Value("${acme.base-url:https://localhost:8443/acme}")
    private String baseUrl;

    @Value("${acme.authorization.expiration-hours:24}")
    private int authorizationExpirationHours;

    /**
     * 주어진 식별자들에 대한 인증을 생성합니다.
     */
    public List<Authorization> createAuthorizations(List<Identifier> identifiers) {
        log.info("Creating authorizations for {} identifiers", identifiers.size());

        return identifiers.stream()
            .map(this::createAuthorization)
            .collect(Collectors.toList());
    }

    /**
     * 단일 식별자에 대한 인증을 생성합니다.
     */
    public Authorization createAuthorization(Identifier identifier) {
        log.info("Creating authorization with baseUrl: {}, expirationHours: {}", baseUrl, authorizationExpirationHours);
        String authorizationId = generateAuthorizationId();
        log.info("Generated authorizationId: {}", authorizationId);
        Instant now = Instant.now();
        Instant expires = now.plusSeconds(authorizationExpirationHours * 3600L);

        // 와일드카드 도메인 여부 확인
        boolean isWildcard = identifier.getValue().startsWith("*.");

        // 기본 HTTP-01 챌린지 생성
        List<Authorization.Challenge> challenges = List.of(
            Authorization.Challenge.builder()
                .type("http-01")
                .url(baseUrl + "/challenge/" + generateChallengeId())
                .token(generateChallengeToken())
                .status("pending")
                .build()
        );

        // 와일드카드 도메인의 경우 DNS-01 챌린지만 허용
        if (isWildcard) {
            challenges = List.of(
                Authorization.Challenge.builder()
                    .type("dns-01")
                    .url(baseUrl + "/challenge/" + generateChallengeId())
                    .token(generateChallengeToken())
                    .status("pending")
                    .build()
            );
        }

        Authorization authorization = Authorization.builder()
            .authorizationId(authorizationId)
            .identifier(identifier)
            .status(Authorization.AuthorizationStatus.PENDING)
            .expires(expires)
            .challenges(challenges)
            .wildcard(isWildcard ? true : null)
            .build();

        authorizations.put(authorizationId, authorization);

        log.info("Created authorization {} for identifier {}:{}",
            authorizationId, identifier.getType(), identifier.getValue());

        return authorization;
    }

    /**
     * 인증 ID로 인증을 조회합니다.
     */
    public Authorization getAuthorization(String authorizationId) {
        return authorizations.get(authorizationId);
    }

    /**
     * 인증 URL을 생성합니다.
     */
    public String getAuthorizationUrl(String authorizationId) {
        return baseUrl + "/authz/" + authorizationId;
    }

    /**
     * 인증 ID를 생성합니다.
     */
    private String generateAuthorizationId() {
        return UUID.randomUUID().toString().replace("-", "");
    }

    /**
     * 챌린지 ID를 생성합니다.
     */
    private String generateChallengeId() {
        return UUID.randomUUID().toString().replace("-", "");
    }

    /**
     * 챌린지 토큰을 생성합니다.
     */
    private String generateChallengeToken() {
        return UUID.randomUUID().toString().replace("-", "");
    }
}